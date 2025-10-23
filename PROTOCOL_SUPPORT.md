# NetDefender 协议支持说明

## 版本
v1.0 - 2025-10-22

---

## 支持的协议

NetDefender当前支持以下协议栈的检测：

### ✅ 数据链路层
- **Ethernet** (以太网)

### ✅ 网络层
- **IPv4**
- **IPv6**

### ✅ 传输层
- **TCP**
- **UDP**
- **ICMP** (ICMPv4 和 ICMPv6)

### ✅ 应用层
通过Suricata检测引擎支持：
- **HTTP/HTTPS**
- **DNS**
- **TLS/SSL**
- **SMTP**
- **FTP**
- **SSH**
- **SMB**
- **其他Suricata支持的应用层协议**

---

## 不支持的协议

以下协议**不在当前支持范围**内：

### ❌ 数据链路层
- **PPP** (Point-to-Point Protocol)
- **PPPoE** (PPP over Ethernet)

### ❌ 传输层
- **SCTP** (Stream Control Transmission Protocol)

### ❌ 隧道协议
- **GRE** (Generic Routing Encapsulation)
- **VXLAN** (Virtual Extensible LAN)
- **Geneve**
- **其他封装协议**

### ❌ VLAN
- **VLAN标签** (802.1Q)
- 如需要VLAN支持，需在DPDK层剥离标签后再传递给桥接层

---

## 设计决策

### 为什么不支持PPP/PPPoE？

1. **使用场景**: PPP/PPPoE主要用于DSL拨号连接
2. **部署环境**: NetDefender主要部署在数据中心和企业网络环境，这些环境使用以太网
3. **简化实现**: 专注于最常见的以太网协议栈

### 为什么不支持SCTP？

1. **使用频率**: SCTP在实际网络流量中占比极低（<0.1%）
2. **复杂度**: SCTP协议复杂，增加测试和维护成本
3. **优先级**: 当前需求专注于TCP/UDP/ICMP这三种最常见的传输层协议
4. **扩展性**: 如未来需要，可通过Suricata的SCTP支持扩展（Suricata原生支持SCTP）

### 为什么不支持隧道协议？

1. **架构选择**: NetDefender设计为在隧道解封装**之后**的位置部署
2. **部署位置**: 通常部署在网络边界或核心交换机镜像端口
3. **简化实现**: 避免处理嵌套协议解析的复杂性
4. **性能考虑**: 隧道解析会增加CPU开销

### 为什么不支持VLAN？

1. **灵活性**: VLAN标签可在DPDK RX配置中剥离
2. **架构清晰**: 桥接层只处理纯净的以太网帧
3. **配置简单**: 通过DPDK配置`DEV_RX_OFFLOAD_VLAN_STRIP`即可

---

## 扩展支持

如果未来需要支持额外的协议，可以：

### 添加SCTP支持

Suricata已原生支持SCTP，只需：
1. 修改`suricata_bridge.c`中的调试日志添加SCTP判断
2. 确保Suricata配置启用SCTP检测
3. 添加SCTP相关的规则

**工作量**: ~1-2小时

### 添加隧道协议支持

需要：
1. 在桥接层添加隧道解封装逻辑
2. 递归处理内层数据包
3. 维护隧道上下文和状态
4. 测试各种隧道组合

**工作量**: ~3-5天

### 添加VLAN支持

两种方案：

**方案1**: DPDK层剥离（推荐）
- 在端口配置中启用`DEV_RX_OFFLOAD_VLAN_STRIP`
- 工作量: ~1小时

**方案2**: 桥接层处理
- 在`mbuf_to_suricata_packet()`中检测VLAN标签
- 提取VLAN ID到`p->vlan_id`字段
- 工作量: ~2-3小时

---

## 性能影响

当前协议支持对性能的影响：

| 协议 | 解析开销 | 状态维护 | 内存占用 |
|------|---------|---------|---------|
| TCP  | 中等     | 高（流重组）| 高 |
| UDP  | 低       | 低      | 低 |
| ICMP | 极低     | 无      | 极低 |

**说明**:
- TCP需要维护连接状态和流重组，开销最大
- UDP无状态，开销最小
- ICMP只需解析头部，几乎无开销

---

## 流量覆盖率

基于典型企业网络流量分析：

| 协议类型 | 流量占比 | NetDefender支持 |
|---------|---------|----------------|
| TCP     | 70-80%  | ✅ 支持 |
| UDP     | 15-25%  | ✅ 支持 |
| ICMP    | 1-5%    | ✅ 支持 |
| SCTP    | <0.1%   | ❌ 不支持 |
| 其他    | <1%     | ❌ 不支持 |

**总覆盖率**: > 95%

---

## 应用层协议检测

通过Suricata引擎，NetDefender可检测以下应用层协议的威胁：

### HTTP/HTTPS
- SQL注入
- XSS攻击
- 恶意文件下载
- C&C通信

### DNS
- DNS隧道
- DGA域名
- DNS放大攻击

### TLS/SSL
- 证书验证
- 协议降级攻击
- 加密流量指纹识别

### SMTP
- 垃圾邮件
- 钓鱼邮件
- 恶意附件

### SMB
- WannaCry, EternalBlue
- 文件共享攻击
- 横向移动检测

### SSH
- 暴力破解
- 异常认证行为

---

## 配置示例

### Suricata配置 (conf/suricata.yaml)

```yaml
# 启用的应用层协议
app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
    smtp:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smb:
      enabled: yes
    # SCTP - 当前禁用
    # sctp:
    #   enabled: no
```

### DPDK配置 (如需VLAN剥离)

```c
// 在netif.c的端口配置中添加
port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
```

---

## 总结

NetDefender专注于支持最常见和最重要的网络协议（TCP/UDP/ICMP），能够覆盖95%以上的企业网络流量。通过简化协议栈，我们实现了更高的性能和更低的维护成本。

如有特殊需求需要支持其他协议，可以根据本文档的扩展指南进行添加。

---

**文档版本**: 1.0
**最后更新**: 2025-10-22
**维护者**: NetDefender Team
