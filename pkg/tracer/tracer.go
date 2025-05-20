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
	"golang.org/x/sys/unix"
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

		// TODO(patrick.pichler): make output nicer
		fmt.Printf("%d\t\t%s\t\t%s\t\t%s\n",
			event.Id,
			typeToStr(event.Qtype),
			unix.ByteSliceToString(event.Name[:]),
			rcodeToStr(event.Rcode),
		)

		continue
	}
}

type parsedDnsMsg struct {
	transactionID uint16
	questionType  string
	name          string
	resultCode    string
}

const (
	RCodeSuccess        = 0 // NoError
	RCodeFormatError    = 1 // FormErr
	RCodeServerFailure  = 2 // ServFail
	RCodeNameError      = 3 // NXDomain
	RCodeNotImplemented = 4 // NotImp
	RCodeRefused        = 5 // Refused
)

func rcodeToStr(rcode uint8) string {
	switch rcode {
	case RCodeSuccess:
		return "Success"
	case RCodeFormatError:
		return "FormatError"
	case RCodeServerFailure:
		return "ServerFailure"
	case RCodeNameError:
		return "NameError"
	case RCodeNotImplemented:
		return "NotImplemented"
	case RCodeRefused:
		return "RCodeRefused"
	}

	return fmt.Sprintf("UNKNOWN (%d)", rcode)
}

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeOPT   = 41

	// Question.Type
	TypeWKS   = 11
	TypeHINFO = 13
	TypeMINFO = 14
	TypeAXFR  = 252
	TypeALL   = 255
)

func typeToStr(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	}

	return fmt.Sprintf("UNKNOWN (%d)", t)
}
