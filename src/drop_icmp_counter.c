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


struct bpf_map_def SEC("maps") cnt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(long),
    .max_entries = 65536,
};


static inline void csum_replace2(uint16_t *sum, uint16_t old, uint16_t new)
{
	uint16_t csum = ~*sum;

	csum += ~old;
	csum += csum < (uint16_t)~old;

	csum += new;
	csum += csum < (uint16_t)new;

	*sum = ~csum;
}

SEC("prog")
int xdp_prog_simple(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;
	
    uint8_t old_ttl;
    long *value;
    
    /* Define headers */
	struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

	/* sanity check needed by the eBPF verifier */
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

    /* let other packets pass */
	if (iph->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	/* drop icmp */
    if (iph->protocol == IPPROTO_ICMP) {
        /* Get source address */
        __be32 source = iph->saddr;
        /* Get value pointer address*/
        value = bpf_map_lookup_elem(&cnt, &source);

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

    /* set the TTL to a pseudorandom number 1..255 */
	old_ttl = iph->ttl;
	iph->ttl = bpf_get_prandom_u32() & 0xff ?: 1;

	/* recalculate the checksum, otherwise the IP stack wil drop it */
	csum_replace2(&iph->check, htons(old_ttl << 8), htons(iph->ttl << 8));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";