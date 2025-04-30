/**
 * @file ids_engine.hpp
 * @brief 入侵检测引擎
 */

#ifndef NETDEFENDER_IDS_ENGINE_HPP
#define NETDEFENDER_IDS_ENGINE_HPP

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <rte_mbuf.h>
#include "netdefender/pattern_matcher.hpp"

namespace netdefender {

/**
 * @brief 警报级别
 */
enum class AlertLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

/**
 * @brief 警报信息
 */
struct Alert {
    std::string rule_id;       /**< 触发规则ID */
    std::string description;   /**< 警报描述 */
    AlertLevel level;          /**< 警报级别 */
    std::string source_ip;     /**< 源IP地址 */
    std::string dest_ip;       /**< 目的IP地址 */
    uint16_t source_port;      /**< 源端口 */
    uint16_t dest_port;        /**< 目的端口 */
    std::string protocol;      /**< 协议 */
    uint64_t timestamp;        /**< 时间戳 */
};

/**
 * @brief 警报回调函数类型
 */
using AlertCallback = std::function<void(const Alert&)>;

/**
 * @brief 入侵检测引擎类
 */
class IDSEngine {
public:
    /**
     * @brief 构造函数
     */
    IDSEngine();

    /**
     * @brief 析构函数
     */
    ~IDSEngine();

    /**
     * @brief 从文件加载规则
     * 
     * @param rules_file 规则文件路径
     * @return bool 成功返回true，失败返回false
     */
    bool loadRulesFromFile(const std::string& rules_file);

    /**
     * @brief 从字符串加载规则
     * 
     * @param rules_str 包含规则的字符串
     * @return bool 成功返回true，失败返回false
     */
    bool loadRulesFromString(const std::string& rules_str);

    /**
     * @brief 分析数据包
     * 
     * @param pkts DPDK mbuf数据包数组
     * @param nb_pkts 数据包数量
     */
    void analyzePackets(struct rte_mbuf** pkts, uint16_t nb_pkts);

    /**
     * @brief 设置警报回调函数
     * 
     * @param callback 警报回调函数
     */
    void setAlertCallback(AlertCallback callback);

    /**
     * @brief 启用或禁用规则
     * 
     * @param rule_id 规则ID
     * @param enabled 是否启用
     * @return bool 成功返回true，失败返回false
     */
    bool setRuleEnabled(const std::string& rule_id, bool enabled);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl; /**< 私有实现 */
};

} // namespace netdefender

#endif /* NETDEFENDER_IDS_ENGINE_HPP */ 