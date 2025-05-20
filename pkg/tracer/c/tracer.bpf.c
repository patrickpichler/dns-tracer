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

#define MAX_DNS_LEN 512

struct event {
  u32 payload_size;
  u8 payload[MAX_DNS_LEN];
};

// Force BTF for event struct to be exported.
const struct event *unused_event __attribute__((unused));

int __always_inline submit(void *data, u16 len) {
  if (len > MAX_DNS_LEN) {
    return 1;
  }

  struct event *evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!evt) {
    return 1;
  }

  evt->payload_size = len;

  if (bpf_probe_read_kernel(&evt->payload, len, data)) {
    bpf_ringbuf_discard(evt, 0);
    return 1;
  }

  bpf_ringbuf_submit(evt, 0);

  return 0;
}

SEC("cgroup_skb/ingress") int handle_ingress(struct __sk_buff *ctx) {
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    bpf_printk("no sock");
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

  submit(data + offset, data_end - (data + offset));

error:
out:
  return 1;
}
