#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "common_kern.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} firewall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[32]);      // domain name
    __type(value, __u32);       // action: 1 = block
} dns_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LIMIT_IP_STORE);
    __type(key, struct ip_lpm_key);
    __type(value, enum ip_status);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ioc_ip_map SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, LIMIT_IP);
//     __type(key, struct ip_lpm_key);
//     __type(value, enum ip_status);
// } rules_map_only_ip SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, LIMIT_IP);
//     __type(key, __u16);
//     __type(value, enum ip_status);
// } rules_map_only_port SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, LIMIT_IP);
//     __type(key, __u8);
//     __type(value, enum ip_status);
// } rules_map_only_protocol SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LIMIT_IP);
    __type(key, struct rule_key);
    __type(value, enum ip_status);
} rules_map SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//     __uint(max_entries, 1024);
//     __type(key, struct rule_key);
//     __type(value, enum ip_status);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
// } rules_map SEC(".maps");


static int parse_query(struct __sk_buff *skb, void *query_start, struct dns_query *q);
//static inline int bpf_strcmplength(char *s1, char *s2, u32 n);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, char[MAX_DNS_NAME_LENGTH]);
  __type(value, struct dns_replace);
} dns_map SEC(".maps");
// static function


// Đẩy thông tin log (IP bị chặn) vào Ring Buffer để gửi lên User Space
static __always_inline void send_event(enum firewall_event_type type, void *data) {
    struct ioc_event *evt;

    evt = bpf_ringbuf_reserve(&firewall_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();

    evt->type = type;

    // Copy payload 
    if (type == FIREWALL_EVT_CONNECT_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        evt->net.saddr_v4 = p->saddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.src_port  = p->src_port;
        evt->net.protocol = p->protocol;
    } else if(type == FIREWALL_EVT_BLOCKED_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        evt->net.saddr_v4 = p->saddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
            __builtin_memcpy(evt->net.saddr_v6, p->saddr_v6, sizeof(p->saddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
            __builtin_memset(evt->net.saddr_v6, 0, sizeof(evt->net.saddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.src_port  = p->src_port;
        evt->net.protocol = p->protocol;
    }
    else {
        // TODO
    }
    bpf_ringbuf_submit(evt, 0);
}


// HÀM NHẬN GÓI TIN THÔ, GỌI CÁC HÀM KIẾM TRA RULE, QUYẾT ĐỊNH DROP/PASS
SEC("xdp")
int xdp_block(struct xdp_md *ctx)
{
    struct net_payload np = {};
    np.status = ALLOW;

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    struct ip_lpm_key lpm_key = {};
    struct rule_key full_key = {};

//IPV4
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end)
            return XDP_PASS;
        if (ip4->ihl < 5)
            return XDP_PASS;

        lpm_key.prefixlen = 32;
        __u32 ip_be = ip4->saddr;
        __builtin_memcpy(lpm_key.data, &ip_be, 4);

        np.family   = AF_INET;
        np.saddr_v4 = ip4->saddr;   

        np.protocol = ip4->protocol;

        void *l4 = (void *)ip4 + ip4->ihl * 4;
        if (l4 + 1 > data_end)
            return XDP_PASS;

        if (ip4->protocol == IPPROTO_TCP) {
            struct tcphdr *th = l4;
            if ((void *)(th + 1) > data_end)
                return XDP_PASS;
            // bpf_printk("TCP src=%u dst=%u ihl=%d tot_len=%u\n",
            //             bpf_ntohs(th->source),
            //             bpf_ntohs(th->dest),
            //             ip4->ihl,
            //             bpf_ntohs(ip4->tot_len));
            np.src_port = bpf_ntohs(th->source);
            np.dport    = bpf_ntohs(th->dest);
        } else if (ip4->protocol == IPPROTO_UDP) {
            struct udphdr *uh = l4;
            if ((void *)(uh + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(uh->source);
            np.dport    = bpf_ntohs(uh->dest);
        }

        full_key.ip_version = 4;
        __builtin_memcpy(&full_key.src.data, &ip4->saddr, 4);
        full_key.src.prefixlen = 32;
        // __builtin_memcpy(&full_key.dst.data, &ip4->daddr, 4);
        // full_key.dst.prefixlen = 32;
        full_key.protocol = ip4->protocol;
        full_key.src_port = np.src_port;
        full_key.dst_port = np.dport;
        
    }

    // IPV6
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        lpm_key.prefixlen = 128;
        __builtin_memcpy(lpm_key.data, &ip6->saddr, 16);
        np.family   = AF_INET6;
        __builtin_memcpy(np.saddr_v6, &ip6->saddr, 16);
        np.protocol = ip6->nexthdr;

        void *l4 = (void *)(ip6 + 1);
        if (l4 + 1 > data_end)
            return XDP_PASS;

        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *th = l4;
            if ((void *)(th + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(th->source);
            np.dport    = bpf_ntohs(th->dest);
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *uh = l4;
            if ((void *)(uh + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(uh->source);
            np.dport    = bpf_ntohs(uh->dest);
        }

        full_key.ip_version = 6;
        __builtin_memcpy(&full_key.src.data, &ip6->saddr, 16);
        full_key.src.prefixlen = 128;
        // __builtin_memcpy(&full_key.dst.data, &ip6->daddr, 16);
        // full_key.dst.prefixlen = 128;
        full_key.protocol = ip6->nexthdr;
        full_key.src_port = np.src_port;
        full_key.dst_port = np.dport;
    }

    // NON-IP
    else {
        return XDP_PASS;
    }
    // lookup IOC map
    enum ip_status *verdict1 = bpf_map_lookup_elem(&ioc_ip_map, &lpm_key);
    if (verdict1) {
        np.status = *verdict1;
    }
    // drop if DENY
    if (np.status == DENY) {
        bpf_printk("chekc check check\n");
        send_event(FIREWALL_EVT_BLOCKED_IP, &np);
        return XDP_DROP;
    }
    // example dst_port = 80
    // if (np.dport == 80) {
    //     // bpf_printk("debug view kernel XDP packet: dst_port=80, drop it\n");
    //     return XDP_DROP;
    // }
    /* -------------------- Lookup rule -------------------- */
    // (ip=any, port=any, protocol=any, dst_port)
    struct rule_key full_key_0_0_0_1 = {};
    __builtin_memcpy(&full_key_0_0_0_1, &full_key, sizeof(full_key));
    __builtin_memset(&full_key_0_0_0_1.src.data, 0, sizeof(full_key_0_0_0_1.src.data)); // any ip
    full_key_0_0_0_1.src.prefixlen = 0;
    full_key_0_0_0_1.src_port = 0; // any port
    full_key_0_0_0_1.protocol = 0; // any protocol
    enum ip_status *verdict_0_0_0_1 = bpf_map_lookup_elem(&rules_map, &full_key_0_0_0_1);
    if (verdict_0_0_0_1) {
        np.status = *verdict_0_0_0_1;
        if (np.status == DENY) {
            send_event(FIREWALL_EVT_BLOCKED_IP, &np);
            return XDP_DROP;
        } 
    }
    // print debug full_key and full_key_0_0_0_1
    // bpf_printk("debug view kernel XDP full_key: ip_version=%d src_ip=%x src_port=%d protocol=%d dst_port=%d\n",
    //             full_key.ip_version,
    //             *((__u32 *)full_key.src.data),
    //             full_key.src_port,
    //             full_key.protocol,
    //             full_key.dst_port);
    // bpf_printk("debug view kernel XDP full_key_0_0_0_1: ip_version=%d src_ip=%x src_port=%d protocol=%d dst_port=%d\n",
    //             full_key_0_0_0_1.ip_version,
    //             *((__u32 *)full_key_0_0_0_1.src.data),
    //             full_key_0_0_0_1.src_port,
    //             full_key_0_0_0_1.protocol,
    //             full_key_0_0_0_1.dst_port);
    // bpf_printk("debug view kernel XDP packet: family=%d protocol=%d src_port=%d dst_port=%d\n",
    //             np.family,
    //             np.protocol,
    //             np.src_port,
    //             np.dport);
    // (ip, port, protocol=any, dst_port=any) 
    struct rule_key full_key_1_1_0_0 = {};
    __builtin_memcpy(&full_key_1_1_0_0, &full_key, sizeof(full_key));
    full_key_1_1_0_0.protocol = 0; // any protocol
    full_key_1_1_0_0.dst_port = 0; // any dst_port
    enum ip_status *verdict_1_1_0_0 = bpf_map_lookup_elem(&rules_map, &full_key_1_1_0_0);
    if (verdict_1_1_0_0) {
        np.status = *verdict_1_1_0_0;
        if (np.status == DENY) {
            send_event(FIREWALL_EVT_BLOCKED_IP, &np);
            return XDP_DROP;
        } 
    }
    // (ip=any, port, protocol=any, dst_port=any)
    
    struct rule_key full_key_0_1_0_0 = {};
    __builtin_memcpy(&full_key_0_1_0_0, &full_key, sizeof(full_key));
    __builtin_memset(&full_key_0_1_0_0.src.data, 0, sizeof(full_key_0_1_0_0.src.data)); // any ip
    full_key_0_1_0_0.src.prefixlen = 0;
    full_key_0_1_0_0.protocol = 0; // any protocol
    full_key_0_1_0_0.dst_port = 0; // any dst_port
    enum ip_status *verdict_0_1_0_0 = bpf_map_lookup_elem(&rules_map, &full_key_0_1_0_0);
    // send_event(FIREWALL_EVT_BLOCKED_IP, &np);
    if (verdict_0_1_0_0) {
        np.status = *verdict_0_1_0_0;
        if (np.status == DENY) {
            send_event(FIREWALL_EVT_BLOCKED_IP, &np);
            return XDP_DROP;
        } 
        
    }

    // (ip, port=any, protocol=any, dst_port=any)
    struct rule_key full_key_1_0_0_0 = {};
    __builtin_memcpy(&full_key_1_0_0_0, &full_key, sizeof(full_key));
    full_key_1_0_0_0.src_port = 0; // any port
    full_key_1_0_0_0.protocol = 0; // any protocol
    full_key_1_0_0_0.dst_port = 0; // any dst_port

    enum ip_status *verdict_1_0_0_0 = bpf_map_lookup_elem(&rules_map, &full_key_1_0_0_0);
    if (verdict_1_0_0_0) {
        np.status = *verdict_1_0_0_0;
        if (np.status == DENY) {
            send_event(FIREWALL_EVT_BLOCKED_IP, &np);
            return XDP_DROP;
        } 
    }
    
    // (ip=any, port=any, protocol, dst_port=any)
    struct rule_key full_key_0_0_1_0 = {};
    __builtin_memcpy(&full_key_0_0_1_0, &full_key, sizeof(full_key));
    __builtin_memset(&full_key_0_0_1_0.src.data, 0, sizeof(full_key_0_0_1_0.src.data)); // any ip
    full_key_0_0_1_0.src.prefixlen = 0;
    full_key_0_0_1_0.src_port = 0; // any port
    full_key_0_0_1_0.dst_port = 0; // any dst_port
    enum ip_status *verdict_0_0_1_0 = bpf_map_lookup_elem(&rules_map, &full_key_0_0_1_0);
    if (verdict_0_0_1_0) {
        np.status = *verdict_0_0_1_0;
        if (np.status == DENY) {
            send_event(FIREWALL_EVT_BLOCKED_IP, &np);
            return XDP_DROP;
        } 
    }



    enum ip_status *verdict = bpf_map_lookup_elem(&rules_map, &full_key);
    if (verdict)
        np.status = *verdict;

    if (np.status == DENY) {
        send_event(FIREWALL_EVT_BLOCKED_IP, &np);
        return XDP_DROP;
    }

    return XDP_PASS;
}

// SO SÁNH ĐUÔI TÊN MIỀN
static __always_inline int match_suffix(const char *name, int name_len,
                                        const char *suffix, int suffix_len)
{
    if (name_len < suffix_len)
        return 0;

    // So sánh từ cuối chuỗi
    for (int i = 0; i < suffix_len; i++) {
        char c1 = name[name_len - suffix_len + i];
        char c2 = suffix[i];
        // Chuyển ký tự hoa -> thường
        if (c1 >= 'A' && c1 <= 'Z')
            c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z')
            c2 += 32;

        if (c1 != c2)
            return 0;
    }
    return 1; // match
}
// Đọc và phân tích gói tin DNS (UDP port 53), tìm kiếm trong dns_map để chặn hoặc thay đổi IP phản hồi
static inline int read_dns(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end) {
        return TC_ACT_OK;
    }

    h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;

        if ((void*)(iph + 1) > data_end) {
            return 0;
        }

        if (iph->protocol != IPPROTO_UDP) {
            return 0;
        }
        __u32 ip_hlen = 0;
        //__u32 poffset = 0;
        //__u32 plength = 0;
    // __u32 ip_total_length = bpf_ntohs(iph->tot_len);

        ip_hlen = iph->ihl << 2;

        if (ip_hlen < sizeof(*iph)) {
            return 0;
        }
        struct udphdr *udph = data + nh_off + sizeof(*iph);

        if ((void*)(udph + 1) > data_end) {
            return 0;
        }
        __u16 src_port = bpf_ntohs(udph->source);
        __u16 dst_port = bpf_ntohs(udph->dest);

        if (src_port == 53 || dst_port == 53) {

            // Get the DNS Header
            
            struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph);
            if ((void*)(dns_hdr + 1) > data_end) {
                return 0;  
            }
            // bpf_printk("DNS packet: qr=%d opcode=%d id=%u", dns_hdr->qr, dns_hdr->opcode, bpf_ntohs(dns_hdr->transaction_id));
            // qr == 0 is a query 
            if (dns_hdr->qr == 0 && dns_hdr->opcode == 0){
                // bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));
            }
            // qr == 1 is a response
            if (dns_hdr->qr ==1 && dns_hdr->opcode ==0 ){
                // Read the query
                void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

                struct dns_query q;
                int query_length = 0;
                query_length = parse_query(skb, query_start, &q);
                if (query_length < 1)
                {
                    return 0;
                }
                // if(match_suffix(q.name, query_length, "examplecom", 10) == 1) {
                //     bpf_printk("Blocked DNS query for name [%s]", q.name);
                //     return TC_ACT_SHOT;
                // }
                struct dns_replace *found_name;
                // Looking up the domain name in the map
                if (sizeof(q.name) != 0) {
                    found_name = bpf_map_lookup_elem(&dns_map, q.name);
                    // print len q.name
                    // bpf_printk("DNS query for name [%s], length %d", q.name, sizeof(q.name));
                    if (found_name > 0) {
                        bpf_printk("Looks like we've found your name [%s]", found_name->name);
                    }
                }
                // Read the DNS response
                struct dns_response *ar_hdr = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + sizeof(*dns_hdr) + query_length;
                if ((void*)(ar_hdr + 1) > data_end) {
                     return 0;  
                }


                __u32 ip;
                
                __u32 poffset = sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + sizeof(*dns_hdr) + query_length + sizeof(*ar_hdr);
                
                // Load data from the socket buffer, poffset starts at the end of the TCP Header
                int ret = bpf_skb_load_bytes(skb, poffset, &ip, sizeof(ip));
                if (ret != 0) {
                    return 0;
                }
                //bpf_printk("%pI4", &ip);
                if (found_name) {
                    bpf_printk("%pI4 -> %pI4", &ip, &found_name->arecord);
                    ret = bpf_skb_store_bytes(skb, poffset, &found_name->arecord, sizeof(found_name->arecord), BPF_F_RECOMPUTE_CSUM);
                    if (ret != 0) {
                        return 0;
                    }
                }
            }

            // //Get a pointer to the start of the DNS query
            // void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

            // struct dns_query q;
            // int query_length = 0;
            // query_length = parse_query(skb, query_start, &q);
            // if (query_length < 1)
            //     {
            //         return 0;
            //     }
            // //bpf_printk("%u %s %u", query_length, q.name, sizeof(q.name));
            // if (bpf_strcmplength(q.name, "github.com", query_length) == 0) {
            //     bpf_printk("woo");
            // }

        }   
    }
    return 0;
}



//TÁCH TÊN MIỀN - DOMAIN NAME TỪ GÓI TIN DNS THÔ
static int parse_query(struct __sk_buff *skb, void *query_start, struct dns_query *q)
{
    void *data_end = (void *)(long)skb->data_end;

    #ifdef DEBUG
    bpf_printk("Parsing query");
    #endif

    uint16_t i;
    void *cursor = query_start;
    int namepos = 0;

    //Fill dns_query.name with zero bytes
    //Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
    __builtin_memset(&q->name[0], 0, sizeof(q->name));
    //Fill record_type and class with default values to satisfy verifier
    q->record_type = 0;
    q->class_ = 0;

    //We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
    //We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
    for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
    {

        //Boundary check of cursor. Verifier requires a +1 here. 
        //Probably because we are advancing the pointer at the end of the loop
        if (cursor + 1 > data_end)
        {
            #ifdef DEBUG
            bpf_printk("Error: boundary exceeded while parsing DNS query name");
            #endif
            break;
        }

        /*
        #ifdef DEBUG
        bpf_printk("Cursor contents is %u\n", *(char *)cursor);
        #endif
        */

        //If separator is zero we've reached the end of the domain query
        if (*(char *)(cursor) == 0)
        {

            //We've reached the end of the query name.
            //This will be followed by 2x 2 bytes: the dns type and dns class.
            if (cursor + 5 > data_end)
            {
                #ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
                #endif
            }
            else
            {
                q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
                q->class_ = bpf_htons(*(uint16_t *)(cursor + 3));
            }

            //Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
            return namepos + 1 + 2 + 2;
        }

        //Read and fill data into struct
        q->name[namepos] = *(char *)(cursor);
   
        namepos++;
        cursor++;
    }

    return -1;
}

// Hook vào luồng dữ liệu đi vào (Ingress) để xử lý DNS
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return read_dns(skb);

}
// Hook vào luồng dữ liệu đi ra (Egress)
SEC("tc/egress")
int tc_egress_(struct __sk_buff *skb)
{
    return read_dns(skb);
}
SEC("cgroup/connect4")
int redirect(struct bpf_sock_addr *ctx)
{
    __u32 old = bpf_ntohl(ctx->user_ip4);
    bpf_printk("Original dest IP: %x", old);
    if (old == 0x01020304) {        
        ctx->user_ip4 = bpf_htonl(0x08080808); // 8.8.8.8
        ctx->user_port = bpf_htons(80);        // port mới
    }
    return 1; // allow
}
// sudo bpftool map show
// sudo bpftool map dump id 11