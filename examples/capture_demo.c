#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

static volatile bool force_quit = false;

/* 信号处理函数 */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* 数据包处理回调函数 */
static void packet_handler(struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_data)
{
    uint16_t i;
    uint64_t *total_packets = (uint64_t*)user_data;
    
    for (i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *pkt = pkts[i];
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
        uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        
        (*total_packets)++;
        
        /* IP包处理 */
        if (ether_type == RTE_ETHER_TYPE_IPV4) {
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            
            /* 仅打印IP协议类型 */
            printf("Packet %lu: IPv4 Protocol: ", *total_packets);
            
            switch (ip_hdr->next_proto_id) {
                case IPPROTO_TCP:
                    printf("TCP\n");
                    break;
                case IPPROTO_UDP:
                    printf("UDP\n");
                    break;
                case IPPROTO_ICMP:
                    printf("ICMP\n");
                    break;
                default:
                    printf("Other (%u)\n", ip_hdr->next_proto_id);
                    break;
            }
        } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
            printf("Packet %lu: IPv6\n", *total_packets);
        } else {
            printf("Packet %lu: Non-IP protocol (0x%04x)\n", *total_packets, ether_type);
        }
        
        /* 释放mbuf */
        rte_pktmbuf_free(pkt);
    }
}

int main(int argc, char *argv[])
{
    int ret;
    uint64_t total_packets = 0;
    uint16_t port_id = 0;
    struct nd_capture_config config = {0};
    
    /* 初始化DPDK EAL */
    ret = nd_dpdk_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error initializing DPDK EAL\n");
    }
    
    /* 检查可用的网口 */
    if (nd_get_available_ports() == 0) {
        rte_exit(EXIT_FAILURE, "No available ports found\n");
    }
    
    /* 设置信号处理函数 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* 初始化端口 */
    ret = nd_port_init(port_id, 1, 1, 128, 128);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error initializing port %d\n", port_id);
    }
    
    /* 配置数据包捕获 */
    config.port_id = port_id;
    config.queue_id = 0;
    config.burst_size = 32;
    config.is_promiscuous = 1;
    
    /* 初始化数据包捕获 */
    ret = nd_packet_capture_init(&config);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error initializing packet capture\n");
    }
    
    printf("Starting packet capture on port %d...\n", port_id);
    printf("Press Ctrl+C to quit\n");
    
    /* 开始捕获数据包 */
    nd_start_capture(packet_handler, &total_packets);
    
    /* 等待退出信号 */
    while (!force_quit) {
        /* 每秒打印一次状态 */
        rte_delay_ms(1000);
        printf("Captured %lu packets so far\n", total_packets);
    }
    
    /* 停止捕获 */
    nd_stop_capture();
    
    /* 清理DPDK资源 */
    nd_dpdk_cleanup();
    
    printf("Exiting... Captured %lu packets total\n", total_packets);
    
    return 0;
} 