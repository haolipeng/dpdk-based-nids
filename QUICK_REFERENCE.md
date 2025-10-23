# Suricata Integration - Quick Reference Guide

## Key Takeaways for DPDK-Based NIDS

### 1. Three-Stage Processing Pipeline

```
Packet Data (from DPDK)
    |
    v
DecodeEthernet() -> DecodeNetworkLayer() -> Decode(IPv4/IPv6) -> Decode(TCP/UDP)
    |
    v
FlowSetupPacket() [Calculate flow_hash]
    |
    v
FlowGetFlowFromHash() [Lookup or create Flow]
    |
    v
StreamTcp() [TCP state machine + reassembly]
    |
    v
Reassembled Stream Data Available for Detection
```

### 2. Critical Initialization (Must be Done Once)

```c
// Global initialization
FlowInitConfig(TRUE);
StreamTcpInitConfig(TRUE);
StreamTcpInitMemuse();

// Per-thread initialization
DecodeThreadVars dtv;
StreamTcpThread *stt;
StreamTcpThreadInit(tv, NULL, (void**)&stt);
```

### 3. Packet Processing Minimal Code

```c
// 1. Decode
Packet *p = PacketGetFromAlloc();
p->ts = get_packet_timestamp();
p->datalink = LINKTYPE_ETHERNET;
p->pktlen = packet_length;
DecodeEthernet(tv, &dtv, p, packet_data, packet_length);

// 2. Flow Lookup
FlowSetupPacket(p);  // Calculates p->flow_hash
Flow *f = FlowGetFlowFromHash(tv, &fls, p, &p->flow);

// 3. TCP Reassembly
if (f && PKT_IS_TCP(p)) {
    StreamTcp(tv, p, stt, NULL);
}

// 4. Cleanup
PACKET_RECYCLE(p);
PacketFreeOrRelease(p);
```

### 4. Memory Configuration

```c
// Flows (global)
flow_config.memcap = 32 * 1024 * 1024;      // 32 MB (minimum)
flow_config.hash_size = 65536;              // 64K buckets
flow_config.prealloc = 10000;               // Pre-allocate flows

// TCP Streams (global)
stream_config.memcap = 64 * 1024 * 1024;                      // 64 MB
stream_config.reassembly_memcap = 256 * 1024 * 1024;          // 256 MB
stream_config.prealloc_sessions = 2048;                       // Per-thread
stream_config.reassembly_depth = 0;                           // Unlimited
```

### 5. Packet Struct Key Fields

**Before calling DecodeEthernet():**
- `p->ts` - timestamp
- `p->pktlen` - total length
- `p->datalink` - LINKTYPE_ETHERNET
- `p->pkt_src` - PKT_SRC_WIRE
- Packet data at: `GET_PKT_DIRECT_DATA(p)` or `p->ext_pkt`

**After DecodeEthernet():**
- `p->ethh` - Ethernet header
- `p->ip4h` or `p->ip6h` - IP header
- `p->tcph`, `p->udph` - L4 header
- `p->src`, `p->dst` - Addresses
- `p->sp`, `p->dp` - Ports
- `p->payload`, `p->payload_len` - L4 payload

### 6. Flow Struct Key Fields

**Created/Looked Up in FlowGetFlowFromHash():**
- `flow->src`, `flow->dst` - Addresses
- `flow->sp`, `flow->dp` - Ports (or ICMP type/code)
- `flow->proto` - IPPROTO_TCP, etc.
- `flow->flow_state` - NEW, ESTABLISHED, CLOSED
- `flow->use_cnt` - Reference counter
- `flow->protoctx` - TcpSession* for TCP
- `flow->lastts` - Last packet timestamp
- `flow->timeout_at` - When flow times out

**Flow Timeout Defaults:**
- New state: 30s
- Established: 3600s (1 hour)
- Closed: 120s
- Emergency mode: 10s / 300s (when memcap pressured)

### 7. TcpSession Key Fields

**Allocated when first TCP packet arrives:**
- `ssn->state` - Current TCP state (TCP_NONE .. TCP_CLOSED)
- `ssn->flags` - STREAMTCP_FLAG_* bits
- `ssn->client` / `ssn->server` - TcpStream objects
- `ssn->reassembly_depth` - Max bytes to reassemble

**TcpStream tracks:**
- `stream->isn` - Initial sequence number
- `stream->next_seq` - Next expected sequence
- `stream->last_ack` - Last acknowledged sequence
- `stream->window` - Current window (post-scale)
- `stream->seg_tree` - Red-black tree of segments
- `stream->sb` - StreamingBuffer for reassembly

### 8. Critical Flags

**Packet Flags (decode.h):**
- `PKT_STREAM_EST` (1<<6) - Part of established stream
- `PKT_STREAM_ADD` (1<<5) - Payload added to reassembled
- `PKT_HAS_FLOW` (1<<8) - Packet has flow attached
- `PKT_WANTS_FLOW` (1<<22) - Decoder wants flow lookup

**Flow Flags:**
- `FLOW_IPV4` / `FLOW_IPV6` - IP version
- `FLOW_TO_DST_SEEN` / `FLOW_TO_SRC_SEEN` - Directions seen
- `FLOW_ACTION_DROP` - Drop all packets in flow
- `FLOW_WRONG_THREAD` - Packet on wrong thread

**TCP Stream Flags:**
- `STREAMTCP_STREAM_FLAG_NOREASSEMBLY` - Disable reassembly
- `STREAMTCP_STREAM_FLAG_DEPTH_REACHED` - Reassembly depth exceeded

### 9. Hash Table Collisions

**Flow hash table design:**
- Hash function: Jenkins hash on (src_ip, dst_ip, src_port, dst_port, proto, vlan, recursion_level)
- Collision resolution: Chaining (linear search)
- Timeout cleanup: Flows checked during lookup, old ones moved to eviction queue
- Lock strategy: Per-bucket mutex (FBLOCK_MUTEX)
- Emergency mode: Shorter timeouts when memory under pressure

### 10. TCP State Machine States

```
TCP_NONE
  |
  +-> TCP_SYN_SENT (sent SYN, waiting for SYN-ACK)
      |
      +-> TCP_SYN_RECV (got SYN, sent SYN-ACK, waiting for ACK)
          |
          +-> TCP_ESTABLISHED (3WHS complete, data can flow)
              |
              +-> TCP_FIN_WAIT1 (sent FIN, waiting for FIN or ACK)
                  |
                  +-> TCP_FIN_WAIT2 (got ACK, waiting for FIN)
                      |
                      +-> TCP_TIME_WAIT (got FIN, sent ACK)
                          |
                          +-> TCP_CLOSED (timeout)
              |
              +-> TCP_CLOSE_WAIT (got FIN, waiting to send FIN)
                  |
                  +-> TCP_LAST_ACK (sent FIN, waiting for ACK)
                      |
                      +-> TCP_CLOSED
```

### 11. Reassembly When Triggered

Reassembly happens automatically when:
1. Stream is ESTABLISHED
2. Data packet received
3. StreamTcpPacket() processes it
4. Segments inserted into seg_tree
5. App layer or detection requests data via StreamReassembleRaw()
6. Reassembler fills gaps and returns contiguous data

Does NOT happen when:
- STREAMTCP_STREAM_FLAG_NOREASSEMBLY set
- Stream reached STREAMTCP_STREAM_FLAG_DEPTH_REACHED
- Memcap exceeded (segments dropped)

### 12. Error Handling

**Common error conditions:**

```c
// Decode failures
if (DecodeEthernet(...) == TM_ECODE_FAILED) {
    // Packet too small or corrupted
    // p->flags & PKT_IS_INVALID set
}

// Flow creation failures
Flow *f = FlowGetFlowFromHash(tv, &fls, p, &f);
if (f == NULL) {
    // Flow allocation failed (memcap exceeded)
    // Packet processed but not tracked
}

// TCP checksum failures
if (stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION) {
    if (StreamTcpValidateChecksum(p) == 0) {
        // Invalid checksum - packet dropped
        return;
    }
}
```

### 13. Performance Optimization Notes

1. **Hashing:**
   - Use pre-calculated flow_hash (set by FlowSetupPacket)
   - Hash calculation is O(1) using Jenkins algorithm
   - Bucket lookup is O(n) in chain (but typically chain length 1)

2. **Memory:**
   - Default configs are conservative (32MB flows, 64MB stream)
   - For high-speed traffic, increase hash_size and memcaps
   - Per-thread session pools reduce lock contention

3. **Reassembly:**
   - Red-black tree insertion is O(log n)
   - Segments in order avoid tree operations
   - Out-of-order segments require gap filling
   - Set reassembly_depth to limit memory use

4. **Flow Timeout:**
   - Checked during lookup (lazy deletion)
   - Emergency mode reduces memory when under pressure
   - Timeout values tunable per protocol

### 14. Linux Kernel Network Stack Differences

Suricata's reassembly differs from Linux kernel:

**Linux kernel:**
- TCP timestamps required for PAWS (Protect Against Wrapped Sequences)
- Window scaling applied globally
- Receives window from latest ACK

**Suricata:**
- Per-stream window tracking
- Per-stream timestamps (last_ts, last_pkt_ts)
- OS-policy based reassembly (Linux, Windows, Old Linux, etc.)
- SACK support with range trees

### 15. Integration Checklist

For DPDK-based NIDS:

- [ ] Call FlowInitConfig() once at startup
- [ ] Call StreamTcpInitConfig() once at startup
- [ ] Call StreamTcpInitMemuse() once at startup
- [ ] Per-thread: DecodeThreadVarsAlloc(tv)
- [ ] Per-thread: StreamTcpThreadInit(tv, NULL, &stt)
- [ ] For each packet: DecodeEthernet() -> FlowGetFlowFromHash() -> StreamTcp()
- [ ] Set p->ts, p->datalink, p->pktlen before decode
- [ ] Call FlowSetupPacket() after decode but before flow lookup
- [ ] Handle NULL returns from FlowGetFlowFromHash()
- [ ] Clean up with PACKET_RECYCLE() or explicit field clearing
- [ ] At shutdown: FlowShutdown(), StreamTcpThreadDeinit(tv, stt)

---

## File Reference

| Component | Header | Implementation | Key Structure |
|-----------|--------|----------------|---------------|
| **Packet Decode** | decode.h | decode.c, decode-ethernet.c | Packet |
| **Ethernet Decode** | decode-ethernet.h | decode-ethernet.c | EthernetHdr |
| **Flow Management** | flow.h | flow.c, flow-hash.c, flow-private.h | Flow, FlowBucket |
| **Flow Hash** | flow-hash.h | flow-hash.c | FlowBucket, FlowKey |
| **TCP Stream** | stream-tcp.h | stream-tcp.c | TcpSession |
| **TCP Private** | stream-tcp-private.h | stream-tcp.c | TcpStream, TcpSegment |
| **Stream Config** | stream-tcp.h | stream-tcp.c | TcpStreamCnf |
| **Reassembly** | stream-tcp-reassemble.h | stream-tcp-reassemble.c | StreamingBuffer |

---

## Configuration Constants

```c
// Flow defaults
FLOW_DEFAULT_HASHSIZE = 65536
FLOW_DEFAULT_MEMCAP = 32 MB
FLOW_DEFAULT_PREALLOC = 10000
FLOW_DEFAULT_NEW_TIMEOUT = 30s
FLOW_DEFAULT_EST_TIMEOUT = 3600s
FLOW_DEFAULT_CLOSED_TIMEOUT = 120s

// Stream TCP defaults
STREAMTCP_DEFAULT_PREALLOC = 2048 (per-thread)
STREAMTCP_DEFAULT_MEMCAP = 64 MB
STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP = 256 MB
STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE = 2560
STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE = 2560
STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED = 5
STREAMTCP_NEW_TIMEOUT = 60s
STREAMTCP_EST_TIMEOUT = 3600s
STREAMTCP_CLOSED_TIMEOUT = 120s
```

---

## Dependency Graph

```
main()
  |
  +-> FlowInitConfig()     [Global, once]
  |   |-> FlowQueueInit()
  |   |-> RandomGet()
  |   |-> SCMallocAligned()
  |   |-> FBLOCK_INIT() [per bucket]
  |   +-> FlowInitFlowProto()
  |
  +-> StreamTcpInitConfig() [Global, once]
  |   |-> SC_ATOMIC_INIT()
  |   |-> StreamTcpInitMemuse()
  |   +-> Config parsing (if config available)
  |
  +-> Per-thread:
  |   +-> StreamTcpThreadInit(tv, NULL, &stt)
  |       |-> StreamTcpReassembleInitThreadCtx()
  |       +-> PoolThreadInit() or PoolThreadExpand()
  |
  +-> Packet processing loop:
  |   +-> DecodeEthernet(tv, &dtv, p, data, len)
  |       +-> DecodeNetworkLayer() [inline dispatch]
  |           +-> DecodeIPV4/DecodeIPV6()
  |               +-> DecodeTCP/DecodeUDP()
  |   |
  |   +-> FlowSetupPacket(p) [if IP+TCP/UDP]
  |   |
  |   +-> FlowGetFlowFromHash(tv, &fls, p, &f)
  |       +-> FlowGetNew()
  |       +-> FlowInit()
  |       +-> FlowIsTimedOut()
  |       +-> FlowCompare()
  |   |
  |   +-> StreamTcp(tv, p, stt, pq)
  |       +-> StreamTcpValidateChecksum()
  |       +-> StreamTcpPacket(tv, p, stt, pq)
  |           +-> StreamTcpStateDispatch()
  |               +-> StreamTcpPacketState{SynSent,Established,etc}()
  |           +-> StreamTcpInsertSegment()
  |           +-> Reassembly (via StreamReassembleRaw if needed)
  |
  +-> Cleanup:
      +-> FlowShutdown()
      +-> StreamTcpThreadDeinit(tv, stt)
```

