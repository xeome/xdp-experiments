// Simple firewall that blocks single source ip(using bpf_map)

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} blocked SEC(".maps");

SEC("prog")
int firewall2(struct xdp_md* ctx) {
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

    // Block certain source ip, using bpf_map lookup or initialize
    __u32 key = 0;
    __u32* value = bpf_map_lookup_elem(&blocked, &key);
    if (!value) {
        __u32 ip_addr = htonl(0x2a2a2a37);
        bpf_map_update_elem(&blocked, &key, &ip_addr, BPF_ANY);
        value = bpf_map_lookup_elem(&blocked, &key);
    }

    if (!value) {
        return XDP_DROP;
    }

    if (iph->saddr == *value) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";