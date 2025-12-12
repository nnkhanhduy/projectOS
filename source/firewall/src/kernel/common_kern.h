#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>      // eBPF helper macro
#include <bpf/bpf_tracing.h>   // bpf_trace_printk
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 32
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define ANY_PORT        0      /* port == 0  => match any port */
#define ANY_PROTOCOL    0      /* proto == 0 => match any protocol */
#ifndef TC_ACT_OK
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_DROP     2
#define TC_ACT_STOLEN   1
#define TC_ACT_QUEUED   3
#define TC_ACT_REPEAT   4
#define TC_ACT_REDIRECT 5
#endif
#define MAX_DNS_NAME_LENGTH 256
#define LIMIT_IP_STORE 40000
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14 /*Ethernet Header Length */
#define EPERM 1
#define LIMIT_IP 1024
#define S_ISLNK(m) (((m) & 0170000) == 0120000)
#define EPERM 1
#define AF_INET 2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ETH_P_IP    0x0800  /* IPv4 */
#define ETH_P_IPV6  0x86DD  /* IPv6 */

enum log_level {
    INFO,
    WARNING,
    ERROR,
    BLOCKED_ACTION
};
struct log_debug {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 level; // Corresponds to enum log_level
    char comm[TASK_COMM_LEN];
    char msg[LOG_MSG_MAX_LEN];
};

enum firewall_event_type {
    FIREWALL_EVT_CONNECT_IP = 0,
    FIREWALL_EVT_BLOCKED_IP
};

struct ip_lpm_key {
    __u32 prefixlen;   // bit length: 32 for IPv4, 128 for IPv6 and /* bit length: 0 => ANY, 32 => /32 IPv4, 128 => /128 IPv6 */
    __u8  data[16];    // IPv4 for 4 first byte, IPv6 for 16 byte
};
struct rule_key {
    struct ip_lpm_key src;  // source
    struct ip_lpm_key dst;  // destination
    __u16 src_port; /* 0 == ANY */
    __u16 dst_port; /* 0 == ANY */
    __u8  protocol;         // IPPROTO_TCP, UDP, ICMP and /* 0 == ANY, otherwise IPPROTO_* */
    __u8  ip_version;       // 4 or 6
};
// struct rule_val {
//     __u8 action;  // 0=DROP, 1=ALLOW, 2=LOG
// };
enum ip_status {
    ALLOW = 0,
    DENY = 1
};
struct net_payload {
    // enum ip_status status;
    __u32 status;
    __u8  family;       // AF_INET / AF_INET6
    __u8  pad[3];
    __u32 saddr_v4;     // IPv4 source
    __u32 daddr_v4;     // IPv4 dest
    __u8  saddr_v6[16]; // IPv6 source
    __u8  daddr_v6[16]; // IPv6 dest
    __u16 src_port;      // source port
    __u16 dport;        // dest port
    __u32 protocol;     // TCP/UDP
};

// Event sent from kernel to user
struct ioc_event {
    __u64 timestamp_ns;       // Time of occurrence
    __u32 pid;                // PID of the process
    __u32 tgid;               // TGID (parent pid)
    __u32 ppid;               // parent PID
    __u32 uid;                // UID of the user running the process
    __u32 gid;                // GID of the user running the process
    enum firewall_event_type type; // Type of event
    union {
        struct net_payload net;
    };
};

struct dns_hdr
{
    uint16_t transaction_id;
    uint8_t rd : 1;      //Recursion desired
    uint8_t tc : 1;      //Truncated
    uint8_t aa : 1;      //Authoritive answer
    uint8_t opcode : 4;  //Opcode
    uint8_t qr : 1;      //Query/response flag
    uint8_t rcode : 4;   //Response code
    uint8_t cd : 1;      //Checking disabled
    uint8_t ad : 1;      //Authenticated data
    uint8_t z : 1;       //Z reserved bit
    uint8_t ra : 1;      //Recursion available
    uint16_t q_count;    //Number of questions
    uint16_t ans_count;  //Number of answer RRs
    uint16_t auth_count; //Number of authority RRs
    uint16_t add_count;  //Number of resource RRs
};

//Used as a generic DNS response
struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class_;
   uint32_t ttl;
   uint16_t data_length;
} __attribute__((packed));

struct dns_query {
    uint16_t record_type;
    uint16_t class_;
    char name[MAX_DNS_NAME_LENGTH];
};
struct dns_replace {
  __u8 name[MAX_DNS_NAME_LENGTH]; // This should be a char but code generation between here and Go..
  __u32 arecord; // This should be a char but code generation between here and Go..
};
#endif // __COMMON_KERN_H