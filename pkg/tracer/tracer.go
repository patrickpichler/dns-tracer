package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/patrickpichler/dns-tracer/pkg/cgroup"
	"golang.org/x/net/dns/dnsmessage"
)

type TracerCfg struct {
}

type Tracer struct {
	log        *slog.Logger
	objs       *tracerObjects
	loaded     atomic.Bool
	cgroupLink link.Link
	cfg        TracerCfg
}

func New(log *slog.Logger, cfg TracerCfg) (Tracer, error) {
	return Tracer{
		log: log,
		cfg: cfg,
	}, nil
}

func (t *Tracer) load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error while removing memlock: %w", err)
	}

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("error while loading bpf spec: %w", err)
	}

	objs := tracerObjects{}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.log.Error(fmt.Sprintf("Verifier error: %+v", ve))
		}

		return fmt.Errorf("error while loading and assigning tracer objs: %w", err)
	}

	t.objs = &objs

	t.loaded.Store(true)

	return nil
}

func (t *Tracer) attach() error {
	if !t.loaded.Load() {
		return errors.New("tracer needs to be loaded before it can be attached")
	}

	cgroupPath, err := cgroup.DetectCgroupPath()
	if err != nil {
		return fmt.Errorf("cannot get cgroup path: %w", err)
	}

	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: t.objs.HandleIngress,
	})
	if err != nil {
		return fmt.Errorf("error while attaching link: %w", err)
	}

	t.cgroupLink = cgroupLink

	return nil
}

func (t *Tracer) Init() error {
	if err := t.load(); err != nil {
		return fmt.Errorf("error loading tracer: %w", err)
	}

	if err := t.attach(); err != nil {
		return fmt.Errorf("error attaching tracer: %w", err)
	}

	return nil
}

func (t *Tracer) Run(ctx context.Context) error {
	eventReader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return fmt.Errorf("error while creating perf array reader: %w", err)
	}

	go func() {
		// We need this goroutine as otherwise we might end forever in case of a SIGTERM.
		<-ctx.Done()
		eventReader.Close()
	}()

	var record ringbuf.Record
	var event tracerEvent

	fmt.Printf("TRANSACTOIN ID\tQTYPE\t\tNAME\t\tRCODE\n")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventReader.ReadInto(&record)
		if err != nil {
			return fmt.Errorf("error reading from perf array: %w", err)
		}

		r := bytes.NewReader(record.RawSample)

		if err := binary.Read(r, binary.LittleEndian, &event); err != nil {
			t.log.Error("error while parsing event from ringbuffer",
				slog.Any("error", err))
			continue
		}

		rawPacket := event.Payload[:]

		result, err := parseDNSMessage(rawPacket)
		if err != nil {
			t.log.Error("error while parsing dns response",
				slog.Any("error", err))
		}

		fmt.Printf("%d\t\t%s\t\t%s\t\t%s\n", result.transactionID, result.questionType, result.name, result.resultCode)

		continue
	}
}

type parsedDnsMsg struct {
	transactionID uint16
	questionType  string
	name          string
	resultCode    string
}

func parseDNSMessage(payload []byte) (parsedDnsMsg, error) {
	parser := &dnsmessage.Parser{}
	hdr, err := parser.Start(payload)
	if err != nil {
		return parsedDnsMsg{}, fmt.Errorf("error parsing header: %w", err)
	}
	question, err := parser.Question()
	if err != nil {
		return parsedDnsMsg{}, fmt.Errorf("error parsing question: %w", err)
	}

	return parsedDnsMsg{
		transactionID: hdr.ID,
		questionType:  typeToStr(question.Type),
		name:          question.Name.String(),
		resultCode:    rcodeToStr(hdr.RCode),
	}, nil
}

func rcodeToStr(rcode dnsmessage.RCode) string {
	switch rcode {
	case dnsmessage.RCodeSuccess:
		return "Success"
	case dnsmessage.RCodeFormatError:
		return "FormatError"
	case dnsmessage.RCodeServerFailure:
		return "ServerFailure"
	case dnsmessage.RCodeNameError:
		return "NameError"
	case dnsmessage.RCodeNotImplemented:
		return "NotImplemented"
	case dnsmessage.RCodeRefused:
		return "RCodeRefused"
	}

	return "UNKNOWN"
}

func typeToStr(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeOPT:
		return "OPT"
	}

	return "UNKNOWN"
}
