#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

typedef unsigned long u64;

struct bpf_map_def SEC("maps") cnt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(long),
    .max_entries = 1000000,
};

static inline __be32 get_tcp_source(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data;
    return iph->saddr;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if (data + nh_off + sizeof(struct ipv6hdr) > data_end)
        return 0;
    return ip6h->nexthdr;
}

SEC("prog")
int xdp_count_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    long *value;
    __u16 h_proto;
    struct ethhdr *eth = data;
    uint64_t nh_off = sizeof(*eth);

    if (data + sizeof(struct ethhdr) >
        data_end) // This check is necessary to pass verification
        return XDP_DROP;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)) {
        h_proto = parse_ipv4(data, nh_off, data_end);
        nh_off += sizeof(struct iphdr);
    } else if (h_proto == htons(ETH_P_IPV6)) {
        h_proto = parse_ipv6(data, nh_off, data_end);
        nh_off += sizeof(struct ipv6hdr);
    } else {
        return XDP_PASS;
    }

    if (h_proto == IPPROTO_ICMP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        __be32 source = iph->saddr;
        value = bpf_map_lookup_elem(&cnt, &source);
        bpf_printk("source ip address is %u\n", source);

        if (value) {
            *value += 1;
        } else {
            long temp = 1;
            bpf_map_update_elem(&cnt, &source, &temp, BPF_ANY);
        }
        if (value && *value > 5)
            return XDP_DROP;
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
