#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "vmlinux.h"              // Kernel BTF types
#include <bpf/bpf_helpers.h>      // eBPF helper macros
#include <bpf/bpf_tracing.h>      // bpf_trace_printk

#define LOG_MSG_MAX_LEN 128        // Độ dài tối đa message log
#define TASK_COMM_LEN   32         // Độ dài tên tiến trình (task->comm)
#define MAX_PATH_LEN    128        // Độ dài tối đa đường dẫn file
#define MAX_POLICY_ENTRIES 64      // Số policy tối đa
#define NAME_MAX        255        // Độ dài tối đa tên file

#define ANY_PORT        0          // Port = 0 → match mọi port
#define ANY_PROTOCOL    0          // Protocol = 0 → match mọi protocol

#ifndef TC_ACT_OK
#define TC_ACT_OK       0          // Cho phép packet đi tiếp
#define TC_ACT_SHOT     2          // Drop packet
#define TC_ACT_DROP     2          // Alias của SHOT
#define TC_ACT_STOLEN   1          // Packet đã bị xử lý
#define TC_ACT_QUEUED   3          // Packet đưa vào queue
#define TC_ACT_REPEAT   4          // Phân loại lại packet
#define TC_ACT_REDIRECT 5          // Redirect packet
#endif

#define MAX_DNS_NAME_LENGTH 256    // Độ dài tối đa tên miền DNS
#define LIMIT_IP_STORE     40000   // Số IP tối đa trong IOC map
#define ETH_P_IP           0x0800  // Ethernet IPv4
#define ETH_HLEN           14      // Độ dài header Ethernet
#define EPERM              1       // Lỗi permission denied
#define LIMIT_IP           1024    // Số rule firewall tối đa
#define S_ISLNK(m) (((m) & 0170000) == 0120000) // Kiểm tra symbolic link
#define AF_INET            2       // IPv4
#define AF_INET6           10      // IPv6
#define ECONNREFUSED       111     // Lỗi connection refused
#define ETH_P_IPV6         0x86DD  // Ethernet IPv6

enum log_level {
    INFO,                          // Log thông tin
    WARNING,                       // Log cảnh báo
    ERROR,                         // Log lỗi
    BLOCKED_ACTION                 // Log hành động bị chặn
};

struct log_debug {
    __u64 timestamp_ns;            // Thời gian xảy ra (ns)
    __u32 pid;                     // PID tiến trình
    __u32 uid;                     // UID người dùng
    __u32 level;                   // Mức log (enum log_level)
    char comm[TASK_COMM_LEN];      // Tên tiến trình
    char msg[LOG_MSG_MAX_LEN];     // Nội dung log
};

enum firewall_event_type {
    FIREWALL_EVT_CONNECT_IP = 0,   // Sự kiện kết nối IP
    FIREWALL_EVT_BLOCKED_IP        // Sự kiện IP bị chặn
};

struct ip_lpm_key {
    __u32 prefixlen;               // Độ dài prefix (/32 IPv4, /128 IPv6, 0 = ANY)
    __u8  data[16];                // Địa chỉ IP (IPv4 dùng 4 byte đầu)
};

struct rule_key {
    struct ip_lpm_key src;         // IP nguồn
    struct ip_lpm_key dst;         // IP đích
    __u16 src_port;                // Port nguồn (0 = ANY)
    __u16 dst_port;                // Port đích (0 = ANY)
    __u8  protocol;                // Protocol L4 (0 = ANY)
    __u8  ip_version;              // Phiên bản IP (4 hoặc 6)
};

enum ip_status {
    ALLOW = 0,                     // Cho phép
    DENY  = 1                      // Chặn
};

struct net_payload {
    __u32 status;                  // Trạng thái firewall (ALLOW/DENY)
    __u8  family;                  // AF_INET hoặc AF_INET6
    __u8  pad[3];                  // Padding cho alignment
    __u32 saddr_v4;                // IP nguồn IPv4
    __u32 daddr_v4;                // IP đích IPv4
    __u8  saddr_v6[16];            // IP nguồn IPv6
    __u8  daddr_v6[16];            // IP đích IPv6
    __u16 src_port;                // Port nguồn
    __u16 dport;                   // Port đích
    __u32 protocol;                // Protocol (TCP/UDP/ICMP)
};

struct ioc_event {
    __u64 timestamp_ns;            // Thời điểm event
    __u32 pid;                     // PID tiến trình
    __u32 tgid;                    // TGID (process id)
    __u32 ppid;                    // PID cha
    __u32 uid;                     // UID người dùng
    __u32 gid;                     // GID người dùng
    enum firewall_event_type type; // Loại sự kiện firewall
    union {
        struct net_payload net;    // Thông tin mạng
    };
};

struct dns_hdr {
    uint16_t transaction_id;       // ID truy vấn DNS
    uint8_t rd : 1;                // Recursion desired
    uint8_t tc : 1;                // Truncated
    uint8_t aa : 1;                // Authoritative answer
    uint8_t opcode : 4;            // Opcode DNS
    uint8_t qr : 1;                // Query (0) / Response (1)
    uint8_t rcode : 4;             // Response code
    uint8_t cd : 1;                // Checking disabled
    uint8_t ad : 1;                // Authenticated data
    uint8_t z  : 1;                // Reserved bit
    uint8_t ra : 1;                // Recursion available
    uint16_t q_count;              // Số câu hỏi
    uint16_t ans_count;            // Số bản ghi trả lời
    uint16_t auth_count;           // Số authority record
    uint16_t add_count;            // Số additional record
} __attribute__((packed));

struct dns_response {
   uint16_t query_pointer;         // Con trỏ đến query
   uint16_t record_type;           // Kiểu record (A, AAAA…)
   uint16_t class_;                // Class (IN)
   uint32_t ttl;                   // Time to live
   uint16_t data_length;           // Độ dài dữ liệu
} __attribute__((packed));

struct dns_query {
    uint16_t record_type;          // Kiểu truy vấn DNS
    uint16_t class_;               // Class truy vấn
    char name[MAX_DNS_NAME_LENGTH];// Tên miền
};

struct dns_replace {
    __u8  name[MAX_DNS_NAME_LENGTH]; // Tên miền cần spoof
    __u32 arecord;                   // IP A record thay thế
};

#endif // __COMMON_KERN_H
