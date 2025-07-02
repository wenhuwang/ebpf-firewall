#ifndef __TC_DUMP_H_
#define __TC_DUMP_H_

#include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include <string.h>

#define VLAN_ID_MASK 0x0FFF

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/

#define VXLAN_PORT 4789

#define MAX_EGRESS_CIDRS 256

#define MAX_DNS_NAME_LENGTH 128
#define MAX_ENTRIES 1024000

// #define TC_ALLOW 1
#define TC_BLOCK 1

static volatile const u32 IFINDEX = 0;

struct vxlan_hdr {
    __be32 vx_flags;
    __be32 vx_vni;
};

#define DIR_INGRESS 1
#define DIR_EGRESS 2

#define printk(fmt, ...)                                   \
	({                                                     \
		bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); \
	})


struct dnshdr
{
	uint16_t transaction_id;
	uint8_t rd : 1;		 // Recursion desired
	uint8_t tc : 1;		 // Truncated
	uint8_t aa : 1;		 // Authoritive answer
	uint8_t opcode : 4;	 // Opcode
	uint8_t qr : 1;		 // Query/response flag
	uint8_t rcode : 4;	 // Response code
	uint8_t cd : 1;		 // Checking disabled
	uint8_t ad : 1;		 // Authenticated data
	uint8_t z : 1;		 // Z reserved bit
	uint8_t ra : 1;		 // Recursion available
	uint16_t q_count;	 // Number of questions
	uint16_t ans_count;	 // Number of answer RRs
	uint16_t auth_count; // Number of authority RRs
	uint16_t add_count;	 // Number of resource RRs
};

typedef struct meta_info {
    u32 ifindex;
    u32 mark;
} meta_info_t;

typedef u16 dir_t;

typedef struct event {
    struct vlan_hdr vlan;
    meta_info_t meta;

    dir_t direction;

    u16 total_len;
#define DATA_SIZE \
    (sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlan_hdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
    u8 data[DATA_SIZE];
#undef DATA_SIZE
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// value stored in egress_cidr_config below
// it contains a ip address as well as net mask
struct cidr_config_val {
  __u32 addr;
  __u32 mask;
};

// Force emitting struct cidr_config_val into the ELF.
const struct cidr_config_val *unused2 __attribute__((unused));

// nested map used to block egress traffic based on CIDR ranges
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_EGRESS_CIDRS);
  __type(key, __u32);   // 0=number of cidrs, 1..256 are CIDRs
  __type(value, __u64); // {IPv4 addr, subnet mask}
} egress_cidr_config SEC(".maps");

struct dnsquery
{
	char name[MAX_DNS_NAME_LENGTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_DNS_NAME_LENGTH);
	__uint(value_size, sizeof(long));
	__uint(max_entries, MAX_ENTRIES);
} egress_dns_config SEC(".maps");

typedef struct config_t {
    u32 mark;
} __attribute__((packed)) config_t;

static volatile const config_t __cfg = {};

#define __validate_skb(skb, hdr) (((u64)hdr + sizeof(*hdr)) <= skb->data_end)

static __always_inline bool
filter_meta(struct __sk_buff *skb, config_t *cfg)
{
    if (cfg->mark && cfg->mark != skb->mark)
        return false;

    return true;
}

static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l2(struct __sk_buff *skb)
{
    void *data = (void *)(long) skb->data;
    void *data_end = (void *)(long) skb->data_end;
    return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

// returns false if allowed
// returns true if blocked
bool filter_egress_cidr(__u32 daddr) {

  // idx 0 stores the length of CIDRs for this particular array
  // It is stored to prevent unneeded iterations and correct handling
  // of the null value 0.0.0.0/0
  __u32 zero = 0;
  __u64 *len = bpf_map_lookup_elem(&egress_cidr_config, &zero);
  if (len == NULL) {
    return false;
  }

  for (int i = 1; i < MAX_EGRESS_CIDRS; i++) {
    if (i > *len) {
      return false;
    }
    __u32 j = i;
    struct cidr_config_val *cidr = bpf_map_lookup_elem(&egress_cidr_config, &j);
    if (cidr == NULL) {
      return false;
    }
    if ((cidr->addr & cidr->mask) == (daddr & cidr->mask)) {
      return true;
    }
  }
  return false;
}

static __always_inline int
parse_query(void *data_end, void *query_start, struct dnsquery *q)
{
	void *cursor = query_start;
	memset(&q->name[0], 0, sizeof(q->name));
	__u8 label_cursor = 0;

	// The loop starts with '-1', because the first char will be '.'
	// and we want to bypass it, check (i == -1) statement for details.
	for (__s16 i = -1; i < MAX_DNS_NAME_LENGTH; i++, cursor++)
	{
        if (cursor + 1 > data_end)
		{
			return -1; // packet is too short.
		}

		if (*(__u8 *)cursor == 0)
		{
			break; // end of domain name.
		}

		if (label_cursor == 0)
		{
			// the cursor is on a label length byte.
			__u8 new_label_length = *(__u8 *)cursor;
			if (cursor + new_label_length > data_end)
			{
				return -1; // packet is too short.
			}
			label_cursor = new_label_length;
			if (i == -1)
			{
				// This is the first label, no need to set '.'
				continue;
			}
			q->name[i] = '.';
			continue;
		}

		label_cursor--;
		char c = *(char *)cursor;
		q->name[i] = c;
	}

	return 1;
}

static __always_inline bool
filter_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long) skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return false;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return false;
    }

    struct iphdr *ip = (data + sizeof(struct ethhdr));

    __u32 daddr = ip->daddr;
    if (filter_egress_cidr(daddr)) {
        return true;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
            return false;
        }

        udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udp->dest == bpf_htons(53)) {
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dnshdr) > data_end) {
                return false;
            }

            struct dnshdr *dns = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
            if (dns->opcode == 0) {
                void *query_start = (void *)dns + sizeof(struct dnshdr);
                struct dnsquery query;
                if (!parse_query(data_end, query_start, &query)) {
                    return false;
                }

                long *pkt_count = bpf_map_lookup_elem(&egress_dns_config, &query.name);
                if (pkt_count) {
                    printk("[BLOCK] DNS QUERY TO %s", &query.name);
                    __sync_fetch_and_add(pkt_count, 1);
                    return true;
                }
                printk("[ALLOW] DNS QUERY TO %s", &query.name);
            }
            printk("DNS QUERY OPCODE %d", dns->opcode);
        }
    }
    return false;
}

static __always_inline bool
filter_pcap(struct __sk_buff *skb) {
    return filter_pcap_l2(skb);
}

static __always_inline bool
filter_tc(struct __sk_buff *skb)
{
    config_t cfg = __cfg;

    return filter_meta(skb, &cfg) && filter_pcap(skb);
}

static __always_inline bool
filter_fentry(struct sk_buff *skb)
{
    config_t cfg = __cfg;

    // filter meta
    if (cfg.mark && cfg.mark != BPF_CORE_READ(skb, mark))
        return false;

    // filter pcap
    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, mac_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool
is_vlan_proto(__be16 proto)
{
    return proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD);
}

static __always_inline bool
is_ipv4_proto(__be16 proto)
{
    return proto == bpf_htons(ETH_P_IP);
}

static __always_inline int
calc_l3_off(struct __sk_buff *skb)
{
    struct ethhdr *eth;
    int l3_off = 0;

    eth = (typeof(eth))((u64)skb->data);
    if (!__validate_skb(skb, eth))
        return 0;

    l3_off += sizeof(*eth);
    if (is_vlan_proto(eth->h_proto))
        l3_off += sizeof(struct vlan_hdr);

    return l3_off;
}

static __always_inline bool
is_vxlan_port(__be16 port)
{
    return port == bpf_htons(VXLAN_PORT);
}

static __always_inline void
copy_headers(void *__skb, event_t *ev, bool is_tc)
{
    struct ethhdr *eth;
    struct vlan_hdr *vh;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct vxlan_hdr *vxh;
    struct icmphdr *icmph;
    int var_off = 0, cpy_off = 0;

#define __memcpy(hdr)                                                         \
    do {                                                                      \
        if (is_tc) {                                                          \
            struct __sk_buff *skb = (struct __sk_buff *)(u64)__skb;           \
            if (bpf_skb_load_bytes_relative(skb, var_off, ev->data + cpy_off, \
                    sizeof(*hdr), BPF_HDR_START_MAC) != 0)                    \
                return;                                                       \
                                                                              \
            hdr = (typeof(hdr))(ev->data + cpy_off);                          \
            cpy_off += sizeof(*hdr);                                          \
            ev->total_len = cpy_off;                                          \
        } else {                                                              \
            struct sk_buff *skb = (struct sk_buff *)(u64)__skb;               \
            void *skb_head = BPF_CORE_READ(skb, head);                        \
            void *data = skb_head + BPF_CORE_READ(skb, mac_header);           \
            if (bpf_probe_read_kernel(ev->data + cpy_off, sizeof(*hdr),       \
                data + var_off) != 0)                                         \
                return;                                                       \
                                                                              \
            hdr = (typeof(hdr))(ev->data + cpy_off);                          \
            cpy_off += sizeof(*hdr);                                          \
            ev->total_len = cpy_off;                                          \
        }                                                                     \
    } while (0)
#define memcpy_hdr(hdr) \
    __memcpy(hdr);      \
    var_off += sizeof(*hdr)
#define memcpy_ip_hdr(hdr) \
    __memcpy(hdr);         \
    var_off += (hdr->ihl * 4)

    memcpy_hdr(eth);

    if (is_vlan_proto(eth->h_proto)) {
        memcpy_hdr(vh);
        if (!is_ipv4_proto(vh->h_vlan_encapsulated_proto))
            return;
    } else if (!is_ipv4_proto(eth->h_proto)) {
        return;
    }

    memcpy_ip_hdr(iph);

    if (iph->protocol == IPPROTO_ICMP) {
        memcpy_hdr(icmph);
    } else if (iph->protocol == IPPROTO_TCP) {
        memcpy_hdr(tcph);
    } else if (iph->protocol == IPPROTO_UDP) {
        memcpy_hdr(udph);

        if (!is_vxlan_port(udph->dest))
            return;

        memcpy_hdr(vxh);

        memcpy_hdr(eth);

        memcpy_ip_hdr(iph);

        if (iph->protocol == IPPROTO_ICMP) {
            memcpy_hdr(icmph);
        } else if (iph->protocol == IPPROTO_TCP) {
            memcpy_hdr(tcph);
        } else if (iph->protocol == IPPROTO_UDP) {
            memcpy_hdr(udph);
        }
    }

#undef memcpy_ip_hdr
#undef memcpy_hdr
#undef __memcpy
}

static __always_inline void
set_output_tc(struct __sk_buff *skb, event_t *ev)
{
    ev->meta.ifindex = IFINDEX;
    ev->meta.mark = skb->mark;

    if (skb->vlan_present) {
        ev->vlan.h_vlan_encapsulated_proto = 1; // indicate tci existing
        ev->vlan.h_vlan_TCI = skb->vlan_tci;
    }

    copy_headers(skb, ev, true);
}

static __always_inline void
set_output_fentry(struct sk_buff *skb, event_t *ev)
{
    ev->meta.ifindex = IFINDEX;
    ev->meta.mark = BPF_CORE_READ(skb, mark);

    if (BPF_CORE_READ(skb, vlan_proto)) {
        ev->vlan.h_vlan_encapsulated_proto = 1; // indicate tci existing
        ev->vlan.h_vlan_TCI = BPF_CORE_READ(skb, vlan_tci);
    }

    copy_headers(skb, ev, false);
}

#endif