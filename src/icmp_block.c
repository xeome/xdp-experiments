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

SEC("prog")
int xdp_prog_simple(struct xdp_md* ctx) {
    /* data and data_end are pointers to the beginning and end of the packet’s raw
    memory. Note that ctx->data and ctx->data_end are of type __u32, so we have
    to perform the casts */
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr* eth = data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);
    struct icmphdr* icmph = (struct icmphdr*)(iph + 1);

    /* sanity check needed by the eBPF verifier
    When accessing the data in struct ethhdr, we must make sure we don't
    access invalid areas by checking whether data + sizeof(struct ethhdr) >
    data_end, and returning without further action if it's true. This check
    is compulsory by the BPF verifer that verifies your program at runtime. */
    if (OVER(eth, data_end))
        return XDP_DROP;

    if (eth->h_proto != ntohs(ETH_P_IP))
        return XDP_PASS;

    /* sanity check needed by the eBPF verifier */
    if (OVER(iph, data_end))
        return XDP_DROP;

    /* sanity check needed by the eBPF verifier */
    if (OVER(icmph, data_end))
        return XDP_DROP;

    /*
        struct iphdr {
        #if defined(__LITTLE_ENDIAN_BITFIELD)
                __u8	ihl:4,
                        version:4;
        #elif defined (__BIG_ENDIAN_BITFIELD)
                __u8	version:4,
                        ihl:4;
        #else
        #error	"Please fix <asm/byteorder.h>"
        #endif
                __u8	tos;
                __be16	tot_len;
                __be16	id;
                __be16	frag_off;
                __u8	ttl;
                __u8	protocol;
                __sum16	check;
                __be32	saddr;
                __be32	daddr;
        };
        This is the ipheader structure from ip.h; we can see the elements we can access
    and their types. We can use iph->protocol to determine whether an incoming
    packet is an ICMP packet or not. */
    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* drop icmp */
    if (iph->protocol == IPPROTO_ICMP)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";