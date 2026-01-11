#ifndef __COMMON_USER_H
#define __COMMON_USER_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <optional>
#include <memory>
#include <thread>
#include <mutex>
#include <future>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
// ===== Linux system =====
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <libgen.h>
#include <elf.h>
#include <sys/prctl.h>
// ===== Security / crypto =====
#include <openssl/sha.h>
#include <openssl/evp.h>

// ===== eBPF / networking =====
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>  // for TC_H_CLSACT
#include <linux/if_link.h>  // for BPF_TC_EGRESS
#include <net/if.h>        // if_nametoindex
// ===== JSON config =====
#include <cjson/cJSON.h>

// ===== eBPF generated header =====
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
#define EPERM     1
#define LIMIT_IP 1024
#define __u64 long long unsigned int
#define __s64 int64_t
#define KERNEL_MINORBITS 20
#define KERNEL_MKDEV(major, minor) ((__u64)(major) << KERNEL_MINORBITS | (minor))
#define BUFFER_SIZE 1024
#define MAX_IFACES 16
#define IPC_PATH "/var/run/firewall.sock"
#ifndef TC_H_CLSACT
#define TC_H_CLSACT    TC_H_MAKE(0xFFFFU, 0)
#endif
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
    __u32 level;
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
struct CallbackContext {
    int dummy; // Placeholder for future use
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
} __attribute__((packed));

//Used as a generic DNS response
struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class_;
   uint32_t ttl;
   uint16_t data_length;
} __attribute__((packed));

struct rate_limit_val {
    __u64 last_time;   // Timestamp of last packet (ns)
    __u64 tokens;      // Current tokens (bytes)
    __u64 rate;        // Rate (bytes per second)
    __u64 capacity;    // Bucket capacity (bytes)
};

struct dns_query {
    uint16_t record_type;
    uint16_t class_;
    char name[MAX_DNS_NAME_LENGTH];
};
struct dns_replace {
  __u8 name[MAX_DNS_NAME_LENGTH]; // This should be a char but code generation between here and Go..
  __u32 arecord; // This should be a char but code generation between here and Go..
};
#endif // __COMMON_USER_H