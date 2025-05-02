/**
 * @file pattern_matcher.hpp
 * @brief 高性能模式匹配引擎
 */

#ifndef NETDEFENDER_PATTERN_MATCHER_HPP
#define NETDEFENDER_PATTERN_MATCHER_HPP

#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace netdefender {

/**
 * @brief 模式匹配结果
 */
struct MatchResult {
    std::string pattern_id;   /**< 匹配的模式ID */
    size_t offset;            /**< 匹配在数据中的偏移量 */
    size_t length;            /**< 匹配的长度 */
};

/**
 * @brief 匹配回调函数类型
 */
using MatchCallback = std::function<void(const MatchResult&)>;

/**
 * @brief 模式匹配引擎类
 * 
 * 支持多种匹配算法：Aho-Corasick、Boyer-Moore、正则表达式等
 */
class PatternMatcher {
public:
    /**
     * @brief 匹配算法类型
     */
    enum class Algorithm {
        AHO_CORASICK,   /**< Aho-Corasick算法，适合多模式匹配 */
        BOYER_MOORE,    /**< Boyer-Moore算法，适合单模式匹配 */
        REGEX           /**< 正则表达式匹配 */
    };

    /**
     * @brief 构造函数
     * 
     * @param algorithm 要使用的匹配算法
     */
    explicit PatternMatcher(Algorithm algorithm = Algorithm::AHO_CORASICK);

    /**
     * @brief 析构函数
     */
    ~PatternMatcher();

    /**
     * @brief 添加模式
     * 
     * @param pattern_id 模式ID
     * @param pattern 要匹配的模式
     * @param is_case_sensitive 是否区分大小写
     * @return bool 成功返回true，失败返回false
     */
    bool addPattern(const std::string& pattern_id, const std::string& pattern, bool is_case_sensitive = true);

    /**
     * @brief 编译所有模式，准备进行匹配
     * 
     * @return bool 成功返回true，失败返回false
     */
    bool compile();

    /**
     * @brief 查找数据中的所有模式匹配
     * 
     * @param data 要搜索的数据
     * @param length 数据长度
     * @param callback 每次匹配调用的回调函数
     * @return int 找到的匹配数量
     */
    int findMatches(const uint8_t* data, size_t length, MatchCallback callback);

    /**
     * @brief 查找数据中的所有模式匹配
     * 
     * @param data 要搜索的数据
     * @param length 数据长度
     * @return std::vector<MatchResult> 匹配结果列表
     */
    std::vector<MatchResult> findMatches(const uint8_t* data, size_t length);

    /**
     * @brief 清除所有模式
     */
    void clear();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl; /**< 私有实现 */
};

} // namespace netdefender

#endif /* NETDEFENDER_PATTERN_MATCHER_HPP */ 