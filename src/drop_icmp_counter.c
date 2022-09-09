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

/* Creating a BPF map for counting ICMP packets as described above */
struct bpf_map_def SEC("maps") cnt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(long),
    .max_entries = 65536,
};

SEC("prog")
int xdp_prog_simple(struct xdp_md *ctx)
{
	/* data and data_end are pointers to the beginning and end of the packet’s raw
    memory. Note that ctx->data and ctx->data_end are of type __u32, so we have
    to perform the casts */
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;
	
    long *value;
    
    /* Define headers */
	struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

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

	/* Check protocol of the packet */
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
    
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";