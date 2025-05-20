#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_kfuncs.h"
#include "types.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024 /* 1 MB */);
} events SEC(".maps");

// Limits as defined per
// https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
#define MAX_NAME_LEN 255
#define MAX_LABEL_LEN 63
#define MAX_UDP_DNS_LEN 512

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  // Sadly the scratch buffer needs to be twice the max name len in
  // order to make the verifier happy.
  __type(value, u8[MAX_NAME_LEN + MAX_NAME_LEN]);
} name_scratch SEC(".maps");

struct event {
  u16 id;
  u16 qtype;
  u8 rcode;
  // According to the spec, a name can at most be 255 chars.
  u8 name[MAX_NAME_LEN];
};

// Force BTF for event struct to be exported.
const struct event *unused_event __attribute__((unused));

struct dns_hdr {
  __be16 id;
  __be16 bits;
  __be16 qdcount;
  __be16 ancount;
  __be16 nscount;
  __be16 arcount;
};

SEC("cgroup_skb/ingress") int handle_ingress(struct __sk_buff *ctx) {
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    bpf_printk("BUG! no sock");
    goto out;
  }

  u32 offset = 0;
  u8 proto = 0;

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  switch (ctx->family) {
  case AF_INET: {
    struct iphdr *iphdrs = data;

    if (data_end < data + sizeof(struct iphdr)) {
      goto out;
    }

    offset += iphdrs->ihl * 4;
    proto = iphdrs->protocol;
  } break;
  case AF_INET6: {
    struct ipv6hdr *iphdrs = data;

    if (data_end < data + sizeof(struct ipv6hdr)) {
      goto out;
    }

    proto = iphdrs->nexthdr;
    offset += sizeof(struct ipv6hdr);
  } break;
  default:
    goto out;
  }

  // We only care about UDP for now.
  if (proto != IPPROTO_UDP) {
    goto out;
  }

  if (data_end < data + offset + sizeof(struct udphdr)) {
    goto out;
  }

  struct udphdr *udphdr = data + offset;

  u16 src_port = bpf_ntohs(udphdr->source);

  // We only use source port 53 as heuristic for DNS traffic for now.
  if (src_port != 53) {
    goto out;
  }

  __s16 datagram_len = bpf_ntohs(udphdr->len);
  if (datagram_len < 0) {
    goto error;
  }

  // For some reason the sk_buff didn't get the full datagram packet.
  if (data_end < data + offset + datagram_len) {
    goto error;
  }

  // Skip forward to UDP packet payload. The UDP header consists of 4 field of 2
  // bytes each (which makes it 8 byte).
  offset += 8;

  struct dns_hdr *dnshdr = data + offset;

  // For some reason the sk_buff didn't get the full datagram packet.
  if (data_end < data + offset + sizeof(struct dns_hdr)) {
    goto error;
  }

  // We only support a single question for now.
  if (dnshdr->qdcount != bpf_htons(1)) {
    goto error;
  }

  offset += sizeof(*dnshdr);

  u32 zero = 0;
  char *name_buf = bpf_map_lookup_elem(&name_scratch, &zero);
  if (!name_buf) {
    goto error;
  }

#define MAX_LABELS 10

  u16 current_size = 0;
  u32 cursor = 0;

  for (int i = 0; i < MAX_LABELS; i++) {
    if (data_end < data + offset + cursor + sizeof(u8)) {
      bpf_printk("BUG! tried reading out of bounds while reading size");
      goto error;
    }

    u8 data_size = *((u8 *)data + offset + cursor);
    // Names and labels are terminated by a zero length octet.
    if (data_size == 0) {
      goto parse_done;
    }

    cursor += 1;

    if ((data_size & 0xc0) != 0) {
      bpf_printk("BUG! only strings are suported now, no pointers");
      goto error;
    }

    if (data_end < data + offset + cursor + data_size) {
      bpf_printk("BUG! tried reading out of bounds while reading data");
      goto error;
    }

    // We also need to count the trailing `.`.
    if ((current_size + data_size + 1) >= MAX_NAME_LEN) {
      bpf_printk("BUG! size bigger than max name len! current_size: %d",
                 current_size);
      goto error;
    }

    // The 0xFF mask is needed to make the verifier happy and proof that
    // we never read outside the bounds.
    if (bpf_probe_read_kernel(name_buf + (current_size & 0xFF), data_size,
                              data + offset + cursor)) {
      goto error;
    }

    current_size += data_size;

    if (current_size < MAX_NAME_LEN - 1) {
      name_buf[current_size] = '.';
    } else {
      bpf_printk("BUG! name too long to add trailing dot");
      goto error;
    }

    current_size += 1;
    cursor += data_size;
  }

  bpf_printk("BUG! couldn't find full name in %d iterations", MAX_LABELS);
  goto error;

parse_done:
  // TODO(patrick.pichler): think about how to do this when supporting pointers.
  offset += cursor;

  name_buf[current_size] = '\0';

  // TODO(patrick.pichler): we for sure can somehow get rid of the name scratch
  // buf and use the reserved ringbuf event directly. It will be somewhat hard
  // to make the verifier happy though (we need twice the max size), not sure if
  // the trade off is worth it.
  struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    goto error;
  }

  event->id = bpf_ntohs(dnshdr->id);
  event->rcode = bpf_ntohs(dnshdr->bits) & 0xF;

  if (data + offset + sizeof(event->qtype) > data_end) {
    bpf_printk("BUG! question section not complete");
    goto error_ringbuf;
  }

  if (bpf_probe_read_kernel(&event->qtype, sizeof(event->qtype),
                            data + offset + 1)) {
    goto error_ringbuf;
  }

  event->qtype = bpf_ntohs(event->qtype);

  __builtin_memcpy(&event->name, name_buf, sizeof(event->name));

  bpf_ringbuf_submit(event, 0);

  goto out;

error_ringbuf:
  bpf_ringbuf_discard(event, 0);

error:
out:
  return 1;
}
