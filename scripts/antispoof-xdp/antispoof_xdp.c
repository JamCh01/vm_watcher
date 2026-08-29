// Reference pre-TCX anti-spoofing boundary (see docs/antispoof-boundary.md).
//
// WHY XDP: on measured kernels (6.12+) the TC ingress hook (where this program's
// rate accounting runs, TCX or clsact) executes BEFORE nftables netdev-ingress
// chains. Source-address enforcement placed at netdev-ingress therefore drops
// spoofed frames only AFTER they were counted into the victim's rate budget —
// a cross-tenant bandwidth DoS (quantified in docs/antispoof-boundary.md).
// XDP runs before TC ingress, so an XDP drop keeps spoofed frames out of the
// accounting entirely.
//
// PER-TAP CONTRACT: a TAP may carry only the source addresses of its own tenant.
// Edit the ALLOWED_* constants below for the tenant of the TAP this program is
// attached to, compile ONE object per TAP (or parameterize via a map for fleets),
// and attach with:
//
//   clang -O2 -target bpf -c antispoof_xdp.c -o antispoof_xdp.o
//   ip link set dev <TAP> xdp obj antispoof_xdp.o sec xdp
//
// TAP RECREATION: netdev hooks and XDP attachments are bound to the device. If
// the TAP is deleted and re-created (new ifindex), BOTH this program and any
// netdev-ingress rules are gone or dead on the old ifindex — re-attach after
// every recreation (the daemon warns about recreations via
// `antispoof_reapply_alerts_total` / SECURITY log lines).
//
// Self-contained on purpose (no kernel headers needed) so it cross-compiles
// anywhere with an LLVM clang (`-target bpf`).
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#define XDP_DROP 1
#define XDP_PASS 2

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// ---- tenant contract for THIS TAP (edit per TAP) ----------------------------
// Allowed IPv4 source, as 4 bytes in network order.
#define ALLOWED_V4 { 10, 99, 0, 1 }
// Allowed IPv6 global source, as 16 bytes in network order.
#define ALLOWED_V6 \
    { 0xfc, 0x00, 0x00, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }
// ------------------------------------------------------------------------------

struct ethhdr_m {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
};
struct iphdr_m {
    __u8 ver_ihl, tos;
    __u16 tot_len;
    __u16 id, frag;
    __u8 ttl, proto;
    __u16 check;
    __u8 saddr[4];
    __u8 daddr[4];
};
struct ipv6hdr_m {
    __u32 vtf;
    __u16 payload_len;
    __u8 nexthdr, hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

static inline __u16 bswap16(__u16 v) { return (v >> 8) | (v << 8); }

__attribute__((section("xdp"), used)) int antispoof_boundary(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr_m *eth = data;
    if ((void *)(eth + 1) > end)
        return XDP_PASS;
    __u16 proto = bswap16(eth->h_proto);
    const __u8 v4[4] = ALLOWED_V4;
    const __u8 v6[16] = ALLOWED_V6;

    if (proto == ETH_P_IP) {
        struct iphdr_m *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > end)
            return XDP_DROP; // truncated header at the boundary: fail closed
        for (int i = 0; i < 4; i++)
            if (ip->saddr[i] != v4[i])
                return XDP_DROP;
        return XDP_PASS;
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr_m *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > end)
            return XDP_DROP;
        // Link-local (fe80::/10) is needed for NDP/SLAAC plumbing: pass.
        if (ip6->saddr[0] == 0xfe && (ip6->saddr[1] & 0xc0) == 0x80)
            return XDP_PASS;
        for (int i = 0; i < 16; i++)
            if (ip6->saddr[i] != v6[i])
                return XDP_DROP;
        return XDP_PASS;
    }
    return XDP_PASS; // ARP and other L2 protocols are not source-checked here
}

char _license[] __attribute__((section("license"))) = "GPL";
