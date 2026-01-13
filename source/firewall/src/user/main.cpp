#include "common_user.h"
#include "connection.h"

extern "C" {
    #include "firewall.skel.h"
}
#include "utils.h"

// Ring buffer
//
static volatile sig_atomic_t exiting = 0;
static int ifindex;

static int handle_firewall_event(void *ctx, void *data, size_t data_sz) {
    const struct ioc_event *evt = (const struct ioc_event *)data;
    // CallbackContext *rb_ctx = (CallbackContext*)ctx; // will use in the future
    // Convert timestamp
    struct timespec ts;
    char timestamp_str[32];
    ts.tv_sec = evt->timestamp_ns / 1000000000ULL;
    ts.tv_nsec = evt->timestamp_ns % 1000000000ULL;
    strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S", localtime(&ts.tv_sec));
    snprintf(timestamp_str + strlen(timestamp_str),
             sizeof(timestamp_str) - strlen(timestamp_str),
             ".%06lu", ts.tv_nsec / 1000);

    // Firewall event type
    const char *type_str = "UNKNOWN";
    if (evt->type == FIREWALL_EVT_BLOCKED_IP) type_str = "NET_BLOCKED";
    else if (evt->type == FIREWALL_EVT_CONNECT_IP) type_str = "NET_CONNECTED";
  
    // use std::cerr all
    switch (evt->type) {
        case FIREWALL_EVT_BLOCKED_IP:
            char ip_str[INET6_ADDRSTRLEN];
            if (evt->net.family == AF_INET) {
                // IPv4
                struct in_addr addr4;
                addr4.s_addr = evt->net.saddr_v4;
                inet_ntop(AF_INET, &addr4, ip_str, sizeof(ip_str));
            } else if (evt->net.family == AF_INET6) {
                struct in6_addr addr6;
                memcpy(&addr6, evt->net.saddr_v6, sizeof(addr6));
                if (inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str)) == NULL) {
                    perror("inet_ntop");
                    snprintf(ip_str, sizeof(ip_str), "InvalidIPv6");

                }
            } else {
                snprintf(ip_str, sizeof(ip_str), "UnknownFamily");
                
            }
            
            std::cerr << "[PACKET CONNECT_EVENT_BLOCKED] " << (evt->net.family == AF_INET ? "AF_INET" : "AF_INET6")
                      << " protocol=" << (evt->net.protocol == 6 ? "TCP" : "UDP")
                      << " -> " << ip_str << ":" << evt->net.src_port << std::endl;

            break;
        // case FIREWALL_EVT_BLOCKED_IP:
        //     char ip_str2[INET6_ADDRSTRLEN];
        //     if (evt->net.family == AF_INET) {
        //         // IPv4
        //         struct in_addr addr4;
        //         addr4.s_addr = evt->net.saddr_v4;   
        //         inet_ntop(AF_INET, &addr4, ip_str2, sizeof(ip_str2));
        //     } else if (evt->net.family == AF_INET6) {
        //         struct in6_addr addr6;
        //         memcpy(&addr6, evt->net.saddr_v6, sizeof(addr6));   
        //         if (inet_ntop(AF_INET6, &addr6, ip_str2, sizeof(ip_str2)) == NULL) {
        //             perror("inet_ntop");
        //             snprintf(ip_str2, sizeof(ip_str2), "InvalidIPv6");
        //         }
        //     } else {
        //         snprintf(ip_str2, sizeof(ip_str2), "UnknownFamily");
        //     }
        default:
            // std::cerr << "Unknown FIREWALL type" << std::endl;
            break;
    }
    return 0;
}

// Thread riêng biệt liên tục gọi ring_buffer__poll để lấy sự kiện từ Kernel
void *firewall_thread(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    while (!exiting) {
        int err = ring_buffer__poll(rb, 10); 
        if (err < 0) {
            fprintf(stderr, "Error polling firewall: %d\n", err);
            break;
        }
    }
    return NULL;
}
static void sig_handler(int sig) {
    exiting = 1;
    printf("[Signal Handler] Received signal %d but ignoring.\n", sig);
}

// Gọi các hàm load BPF, attach XDP/TC và khởi động thread
int main(int argc, char **argv) {
    CallbackContext rb_ctx;
    pthread_t firewall_thread_id;
    struct firewall_bpf *skel_firewall = NULL;
    struct ring_buffer *rb_firewall = NULL;
    struct bpf_tc_hook tc_ingress_hook = {};
    struct bpf_tc_opts tc_ingress_opts = {};
    struct bpf_tc_hook tc_egress_hook = {};
    struct bpf_tc_opts tc_egress_opts = {};
    // struct bpf_tc_hook tc_hook = {};
    // struct bpf_tc_opts tc_opts = {};
    int tc_fd;
    int err_all; 
    std::vector<unsigned int> all_val;
    pid_t pid = getpid();         // Process ID
    pid_t ppid = getppid();       // Parent PID
    char process_name[17] = {0};
    prctl(PR_GET_NAME, (unsigned long)process_name);

    char ifname[IF_NAMESIZE] = {0}; 
    int xdp_prog_fd = 0;



    // Load and verify BPF program - LOAD VÀ VERIFY CHƯƠNG TRÌNH BPF VÀO KERNEL
    // Load and verify BPF program
    skel_firewall = firewall_bpf__open_and_load();
    if (!skel_firewall) {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        return 1;
    }

    UnixServer server(IPC_PATH, skel_firewall, &exiting);

    // Load initial rules
    err_all = load_firewall_rules_into_map(skel_firewall, bpf_map__fd(skel_firewall->maps.rules_map), "firewall_configs.json");
    if (err_all) fprintf(stderr, "Warning: Failed to load firewall rules\n");

    load_ioc_ip_into_kernel_map(skel_firewall, "ioc_ip.txt");
    load_dns_ioc_map(skel_firewall, "ioc_dns.json");

    // Interface selection Logic
    if (argc > 1) {
        strncpy(ifname, argv[1], IF_NAMESIZE - 1);
        ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            std::cerr << "Invalid interface name argument: " << ifname << std::endl;
            goto cleanup;
        }
    } else {
        // Auto-detect default interface
        all_val = get_all_default_ifindexes();
        if (!all_val.empty()) {
            ifindex = all_val[0];
            if_indextoname(ifindex, ifname);
        } else {
            // Fallback
            ifindex = if_nametoindex("eth0");
            if (ifindex > 0) strcpy(ifname, "eth0");
            else {
                ifindex = if_nametoindex("lo");
                if (ifindex > 0) strcpy(ifname, "lo");
                else {
                    std::cerr << "Failed to detect any suitable interface." << std::endl;
                    goto cleanup;
                }
            }
        }
    }
    std::cout << "Selected interface: " << ifname << " (index: " << ifindex << ")" << std::endl;

    xdp_prog_fd = bpf_program__fd(skel_firewall->progs.xdp_block);
    // Try native mode first
    err_all = bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err_all) {
        std::cerr << "XDP Native attach failed (" << err_all << "), trying SKB mode..." << std::endl;
        err_all = bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    }
    
    if(err_all) {
        std::cerr << "Failed to attach BPF program to interface " << ifname << " (Error: " << err_all << ")" << std::endl;
        goto cleanup;
    }

    // Attack TC program
    // --- Add clsact for TC ---
    char tc_cmd[256];
    snprintf(tc_cmd, sizeof(tc_cmd), "tc qdisc add dev %s clsact 2>/dev/null", ifname);
    system(tc_cmd);

    // --- TC Ingress ---
   
    tc_ingress_hook.sz = sizeof(tc_ingress_hook);
    tc_ingress_hook.ifindex = ifindex;
    tc_ingress_hook.attach_point = BPF_TC_INGRESS;

    err_all = bpf_tc_hook_create(&tc_ingress_hook);
    if (err_all && err_all != -EEXIST) { std::cerr << "Failed to create TC ingress hook\n"; goto cleanup; }

    tc_ingress_opts.sz = sizeof(tc_ingress_opts);
    tc_ingress_opts.prog_fd = bpf_program__fd(skel_firewall->progs.tc_ingress);

    if (bpf_tc_attach(&tc_ingress_hook, &tc_ingress_opts) < 0) {
        std::cerr << "Failed to attach TC ingress program\n"; goto cleanup;
    }

    // --- TC Egress ---
    
    tc_egress_hook.sz = sizeof(tc_egress_hook);
    tc_egress_hook.ifindex = ifindex;
    tc_egress_hook.attach_point = BPF_TC_EGRESS;

    err_all = bpf_tc_hook_create(&tc_egress_hook);
    if (err_all && err_all != -EEXIST) { std::cerr << "Failed to create TC egress hook\n"; goto cleanup; }

    tc_egress_opts.sz = sizeof(tc_egress_opts);
    tc_egress_opts.prog_fd = bpf_program__fd(skel_firewall->progs.tc_egress_);

    if (bpf_tc_attach(&tc_egress_hook, &tc_egress_opts) < 0) {
        std::cerr << "Failed to attach TC egress program\n"; goto cleanup;
    }

    // system("tc qdisc add dev ens33 clsact 2>/dev/null");

    // // --- Setup TC hook ---
    // tc_hook.sz = sizeof(tc_hook);
    // tc_hook.ifindex = ifindex;
    // tc_hook.attach_point = BPF_TC_EGRESS;

    // err_all = bpf_tc_hook_create(&tc_hook);
    // if (err_all && err_all != -EEXIST) {
    //     std::cerr << "Failed to create TC hook\n";
    //     goto cleanup;
    // }

    // // --- Attach TC program ---
    // tc_opts.sz = sizeof(tc_opts);
    // tc_opts.prog_fd = bpf_program__fd(skel_firewall->progs.tc_block);

    // if (bpf_tc_attach(&tc_hook, &tc_opts) < 0) {
    //     std::cerr << "Failed to attach TC program\n";
    //     goto cleanup;
    // }

    std::cerr << "Welcome to the Firewall Linux Project!" << std::endl;
    // Set up ring buffer to receive events
    rb_firewall = ring_buffer__new(bpf_map__fd(skel_firewall->maps.firewall_events),
                                   handle_firewall_event,
                                   &rb_ctx,
                                   NULL);
    if (!rb_firewall) {
        std::cerr << "Failed to create ring buffer for firewall events" << std::endl;
        goto cleanup;
    }
    std::cerr <<  "PID: " << pid << ", Name: " << process_name << " [user space main.c] Watching for network events... Ctrl+C to stop." << std::endl;
    if (pthread_create(&firewall_thread_id, NULL, firewall_thread, rb_firewall) != 0) {
        std::cerr << "Failed to create firewall thread" << std::endl;
    }
    if (!server.start()) {
        std::cerr << "Failed to start IPC server\n";
    }
    while (!exiting) {
        sleep(1);
    }
    pthread_join(firewall_thread_id, NULL);
    server.stop();
cleanup:
    if (tc_ingress_opts.prog_fd > 0) {
        bpf_tc_detach(&tc_ingress_hook, &tc_ingress_opts);
    }
    if (tc_ingress_hook.ifindex > 0) {
        bpf_tc_hook_destroy(&tc_ingress_hook);
    }

    // --- Detach TC egress ---
    if (tc_egress_opts.prog_fd > 0) {
        bpf_tc_detach(&tc_egress_hook, &tc_egress_opts);
    }
    if (tc_egress_hook.ifindex > 0) {
        bpf_tc_hook_destroy(&tc_egress_hook);
    }

    // --- Remove clsact qdisc ---
    // --- Remove clsact qdisc ---
    snprintf(tc_cmd, sizeof(tc_cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    system(tc_cmd);

    if (rb_firewall) {
        ring_buffer__free(rb_firewall);
    }
    if (skel_firewall) {
        firewall_bpf__destroy(skel_firewall);
    }
    return 0;
}
//https://medium.com/@seantywork/firewall-iptables-netfilter-kernel-module-and-ebpf-xdp-b7a563711ee6