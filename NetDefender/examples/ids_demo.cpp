#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <signal.h>
#include <netdefender/dpdk_init.h>
#include <netdefender/packet_capture.h>
#include <netdefender/ids_engine.hpp>

// 全局变量
static volatile bool force_quit = false;
static netdefender::IDSEngine ids_engine;

// 信号处理函数
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        std::cout << "\nSignal " << signum << " received, preparing to exit...\n";
        force_quit = true;
    }
}

// 警报回调函数
void alert_callback(const netdefender::Alert& alert)
{
    // 获取当前时间
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    
    // 打印警报信息
    std::cout << "-------- ALERT --------\n";
    std::cout << "Time: " << std::put_time(std::localtime(&time_point), "%Y-%m-%d %H:%M:%S") << "\n";
    std::cout << "Rule ID: " << alert.rule_id << "\n";
    std::cout << "Description: " << alert.description << "\n";
    std::cout << "Level: ";
    
    switch (alert.level) {
        case netdefender::AlertLevel::LOW:
            std::cout << "LOW\n";
            break;
        case netdefender::AlertLevel::MEDIUM:
            std::cout << "MEDIUM\n";
            break;
        case netdefender::AlertLevel::HIGH:
            std::cout << "HIGH\n";
            break;
        case netdefender::AlertLevel::CRITICAL:
            std::cout << "CRITICAL\n";
            break;
    }
    
    std::cout << "Source: " << alert.source_ip << ":" << alert.source_port << "\n";
    std::cout << "Destination: " << alert.dest_ip << ":" << alert.dest_port << "\n";
    std::cout << "Protocol: " << alert.protocol << "\n";
    std::cout << "-----------------------\n";
}

// 数据包处理回调函数
static void packet_handler(struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_data)
{
    uint64_t *total_packets = static_cast<uint64_t*>(user_data);
    
    // 更新包计数
    *total_packets += nb_pkts;
    
    // 使用IDS引擎分析数据包
    ids_engine.analyzePackets(pkts, nb_pkts);
    
    // 处理完成后释放数据包
    for (uint16_t i = 0; i < nb_pkts; i++) {
        rte_pktmbuf_free(pkts[i]);
    }
}

int main(int argc, char *argv[])
{
    int ret;
    uint64_t total_packets = 0;
    uint16_t port_id = 0;
    struct nd_capture_config config = {0};
    
    // 初始化DPDK
    ret = nd_dpdk_init(argc, argv);
    if (ret < 0) {
        std::cerr << "Error initializing DPDK EAL" << std::endl;
        return -1;
    }
    
    // 检查可用的网口
    if (nd_get_available_ports() == 0) {
        std::cerr << "No available ports found" << std::endl;
        return -1;
    }
    
    // 设置信号处理函数
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化端口
    ret = nd_port_init(port_id, 1, 1, 128, 128);
    if (ret < 0) {
        std::cerr << "Error initializing port " << port_id << std::endl;
        return -1;
    }
    
    // 配置数据包捕获
    config.port_id = port_id;
    config.queue_id = 0;
    config.burst_size = 32;
    config.is_promiscuous = 1;
    
    // 初始化数据包捕获
    ret = nd_packet_capture_init(&config);
    if (ret < 0) {
        std::cerr << "Error initializing packet capture" << std::endl;
        return -1;
    }
    
    // 设置IDS引擎警报回调
    ids_engine.setAlertCallback(alert_callback);
    
    // 从规则文件加载规则
    const char* rules_file = "rules/default.rules";
    if (argc > 1) {
        rules_file = argv[1];
    }
    
    if (!ids_engine.loadRulesFromFile(rules_file)) {
        std::cerr << "Warning: Failed to load rules from " << rules_file << std::endl;
        std::cerr << "Continuing without rules..." << std::endl;
    } else {
        std::cout << "Rules loaded from " << rules_file << std::endl;
    }
    
    std::cout << "Starting IDS on port " << port_id << "..." << std::endl;
    std::cout << "Press Ctrl+C to quit" << std::endl;
    
    // 开始捕获数据包
    nd_start_capture(packet_handler, &total_packets);
    
    // 等待退出信号
    while (!force_quit) {
        // 每秒打印一次状态
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Analyzed " << total_packets << " packets so far" << std::endl;
    }
    
    // 停止捕获
    nd_stop_capture();
    
    // 清理DPDK资源
    nd_dpdk_cleanup();
    
    std::cout << "Exiting... Analyzed " << total_packets << " packets total" << std::endl;
    
    return 0;
} 