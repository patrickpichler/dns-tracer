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

struct event {
  u32 payload_size;
};

// Force BTF for event struct to be exported.
const struct event *unused_event __attribute__((unused));

#define BUFFER_SIZE 256
#define min(x, y) ((x) < (y) ? (x) : (y))

int __always_inline submit(struct bpf_dynptr *payload) {
  struct bpf_dynptr ringbuf_ptr;

  u32 payload_size = bpf_dynptr_size(payload);

  if (bpf_ringbuf_reserve_dynptr(&events, sizeof(struct event) + payload_size,
                                 0, &ringbuf_ptr) < 0) {
    goto error;
  }

  struct event *evt = bpf_dynptr_data(&ringbuf_ptr, 0, sizeof(struct event));
  if (!evt) {
    goto error;
  }

  evt->payload_size = payload_size;

  // Until bpf_dynptr_copy lands in the kernel, we need to copy from the skb
  // dynptr to the ringbuf dynptr in chunks.
  // https://lore.kernel.org/bpf/20250221221400.672980-1-mykyta.yatsenko5@gmail.com/
  u8 buf[BUFFER_SIZE];
  void *chunk;
  int chunk_size, off;
  u32 i, chunk_cnt, err;

  chunk_cnt = (payload_size + BUFFER_SIZE - 1) / BUFFER_SIZE;

  bpf_for(i, 0, chunk_cnt) {
    off = BUFFER_SIZE * i;
    chunk_size = min(payload_size - off, BUFFER_SIZE);

    // Force verifier to be happy and that we do not read outside our buffer.
    asm volatile("%[size] &= 0xFFFF;\n" ::[size] "r"(chunk_size));
    asm volatile("if %[size] <= %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n" ::[size] "r"(chunk_size),
                 [max_size] "i"(BUFFER_SIZE));

    if (chunk_size == BUFFER_SIZE) {
      chunk = bpf_dynptr_slice(payload, off, buf, BUFFER_SIZE);
      if (!chunk) {
        bpf_printk("BUG! NULL pkt slice pointer");
        goto error;
      }
    } else {
      err = bpf_dynptr_read(buf, chunk_size, payload, off, 0);
      if (err) {
        bpf_printk("BUG! Failed to read packet data err = %d", err);
        goto error;
      }
      chunk = buf;
    }

    err = bpf_dynptr_write(&ringbuf_ptr, sizeof(struct event) + off, chunk,
                           chunk_size, 0);
    if (err) {
      bpf_printk("BUG! Failed to write ringbuf data err = %d", err);
      goto error;
    }
  }

  bpf_ringbuf_submit_dynptr(&ringbuf_ptr, 0);
  return 0;

error:
  bpf_ringbuf_discard_dynptr(&ringbuf_ptr, 0);
  return 1;
}

SEC("cgroup_skb/ingress")
int handle_ingress(struct __sk_buff *ctx) {

  struct bpf_dynptr data;
  if (bpf_dynptr_from_skb(ctx, 0, &data)) {
    goto error;
  }

  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    bpf_printk("no sock");
    goto out;
  }

  u32 offset = 0;
  u8 proto = 0;

  switch (ctx->family) {
  case AF_INET: {
    struct iphdr *iphdrs =
        bpf_dynptr_slice(&data, 0, NULL, bpf_core_type_size(struct iphdr));
    if (!iphdrs) {
      goto error;
    }

    proto = BPF_CORE_READ(iphdrs, protocol);
    offset += iphdrs->ihl * 4;
  } break;
  case AF_INET6: {
    struct ipv6hdr *iphdrs =
        bpf_dynptr_slice(&data, 0, NULL, bpf_core_type_size(struct ipv6hdr));
    if (!iphdrs) {
      goto error;
    }

    proto = BPF_CORE_READ(iphdrs, nexthdr);
    offset += bpf_core_type_size(struct ipv6hdr);
  } break;
  default:
    goto out;
  }

  // We only care about UDP for now.
  if (proto != IPPROTO_UDP) {
    goto out;
  }

  struct udphdr *udphdr =
      bpf_dynptr_slice(&data, offset, NULL, bpf_core_type_size(struct udphdr));
  if (!udphdr) {
    goto error;
  }

  u16 src_port = bpf_ntohs(udphdr->source);

  // We only use source port 53 as heuristic for DNS traffic for now.
  if (src_port != 53) {
    goto out;
  }

  u16 datagram_len = bpf_ntohs(udphdr->len);

  // For some reason the sk_buff didn't get the full datagram packet.
  if (datagram_len != bpf_dynptr_size(&data) - offset) {
    goto error;
  }

  // Skip forward to UDP packet payload. The UDP header consists of 4 field of 2
  // bytes each (which makes it 8 byte).
  offset += 8;

  struct bpf_dynptr payload;
  if (bpf_dynptr_clone(&data, &payload)) {
    goto error;
  }

  if (bpf_dynptr_adjust(&payload, offset, bpf_dynptr_size(&data))) {
    goto error;
  }

  // TODO(patrick.pichler): look into parsing payload inside eBPF
  submit(&payload);

error:
out:
  return 1;
}
