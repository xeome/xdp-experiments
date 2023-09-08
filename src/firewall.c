// Simple firewall that blocks single source ip

#include <stdint.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#define OVER(x, d) (x + 1 > (typeof(x))d)

// Drop ip 42.42.42.55
#define DROP_SRC_IP htonl(0x2a2a2a37)

SEC("prog")
int xdp_firewall(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr* eth = data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);

    // Sanity checks
    if (OVER(eth, data_end))
        return XDP_DROP;

    if (eth->h_proto != ntohs(ETH_P_IP))
        return XDP_PASS;

    if (OVER(iph, data_end))
        return XDP_DROP;

    // Block certain source ip
    if (iph->saddr == DROP_SRC_IP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}