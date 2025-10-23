# Suricata 6.0.10 Packet Decode, Flow Management, and TCP Stream Reassembly Analysis

## Executive Summary

This document provides a detailed analysis of Suricata's packet processing pipeline for implementing a DPDK-based NIDS. The system follows a three-stage approach: packet decode, flow management, and stream reassembly.

---

## 1. PACKET DECODE PROCESS

### 1.1 DecodeEthernet() Function Overview

**Location:** `/src/decode-ethernet.c` (lines 41-64)

```c
int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    
    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL))
        return TM_ECODE_FAILED;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, SCNtohs(p->ethh->eth_type));

    DecodeNetworkLayer(tv, dtv, SCNtohs(p->ethh->eth_type), p,
            pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}
```

### 1.2 Decode Cascade

After DecodeEthernet(), the decode chain continues:

1. **DecodeEthernet()** extracts Ethernet header
2. **DecodeNetworkLayer()** (inline, decode.h:1285-1338) dispatches based on EtherType:
   - `ETHERNET_TYPE_IP` → DecodeIPV4()
   - `ETHERNET_TYPE_IPV6` → DecodeIPV6()
   - `ETHERNET_TYPE_VLAN` → DecodeVLAN()
   - `ETHERNET_TYPE_PPPOE_SESS` → DecodePPPOESession()
   - etc.

3. **DecodeIPV4()** or **DecodeIPV6()** extracts IP headers and dispatches to L4:
   - TCP → DecodeTCP()
   - UDP → DecodeUDP()
   - ICMP → DecodeICMPV4() / DecodeICMPV6()
   - etc.

4. **DecodeTCP()** / **DecodeUDP()** extract L4 headers and set payload pointer

### 1.3 Packet Fields Populated During Decode

After successful decode, these Packet structure fields are populated:

**Ethernet Layer:**
- `p->ethh` - Pointer to EthernetHdr

**IP Layer (v4 or v6, mutually exclusive):**
- `p->ip4h` - Pointer to IPv4 header
- `p->ip6h` - Pointer to IPv6 header
- `p->src` - Source address (17 bytes)
- `p->dst` - Destination address (17 bytes)
- `p->proto` - Protocol number (IPPROTO_TCP, IPPROTO_UDP, etc.)

**Transport Layer:**
- `p->sp` - Source port (TCP/UDP) or ICMP type
- `p->dp` - Destination port (TCP/UDP) or ICMP code
- `p->tcph` - TCP header pointer
- `p->udph` - UDP header pointer
- `p->icmpv4h` / `p->icmpv6h` - ICMP header pointers

**Payload:**
- `p->payload` - Pointer to L4 payload data
- `p->payload_len` - Length of payload

**Metadata:**
- `p->pktlen` - Total packet length
- `p->vlan_id[2]` - VLAN IDs if present
- `p->recursion_level` - Encapsulation depth (for tunnels)

### 1.4 Setting Up Packet Before Calling DecodeEthernet()

**Essential Fields to Initialize:**

```c
// Allocate or get packet from pool
Packet *p = PacketGetFromAlloc();  // Or from packet pool

// Initialize packet structure (clears fields)
PACKET_INITIALIZE(p);

// Set critical fields
p->ts = packet_timestamp;  // struct timeval with packet capture time
p->pktlen = total_packet_length;

// For packets from DPDK or custom sources, either:
// Option 1: Use direct buffer (packet data right after Packet struct)
//   (buffer is at: (uint8_t *)((p) + 1))

// Option 2: Use external buffer
p->ext_pkt = malloc(packet_length);
memcpy(p->ext_pkt, packet_data, packet_length);

// Set datalink type
p->datalink = LINKTYPE_ETHERNET;  // DLT_EN10MB

// Set packet source
p->pkt_src = PKT_SRC_WIRE;

// Now call the decoder
int status = DecodeEthernet(tv, dtv, p, packet_data, packet_length);
```

### 1.5 PKT_STREAM_ESTABLISHED Flag

**Definition:** Located in decode.h as PKT_STREAM_EST (line 1162)

```c
#define PKT_STREAM_EST  (1<<6)  // Packet is part of established stream
```

**When Set:**
- Set when a TCP packet belongs to an ESTABLISHED TCP session
- Set during StreamTcp() processing after TCP state machine confirms connection

**Usage:**
- Indicates reassembly should be performed
- Signals that stream data is available for detection
- Used in logging and output modules

**Related Flags:**
- `PKT_STREAM_ADD` (1<<5) - Payload was added to reassembled stream
- `PKT_STREAM_EOF` (1<<7) - Stream reached EOF

---

## 2. FLOW MANAGEMENT

### 2.1 Flow Structure Definition

**Location:** `/src/flow.h` (lines 355-505)

```c
typedef struct Flow_
{
    // Flow header (static after init, read-only without lock)
    FlowAddress src, dst;
    union {
        Port sp;        // TCP/UDP source port
        struct { uint8_t type; uint8_t code; } icmp_s;
    };
    union {
        Port dp;        // TCP/UDP destination port
        struct { uint8_t type; uint8_t code; } icmp_d;
    };
    uint8_t proto;                  // IPPROTO_TCP, IPPROTO_UDP, etc.
    uint8_t recursion_level;        // For tunnels
    uint16_t vlan_id[2];            // VLAN identifiers
    FlowRefCount use_cnt;           // Reference counter
    uint8_t vlan_idx;
    
    uint32_t timeout_at;            // When flow will timeout
    FlowThreadId thread_id[2];      // Assigned thread IDs [toserver][toclient]
    struct Flow_ *next;             // Hash chain link
    struct LiveDevice_ *livedev;
    
    uint32_t flow_hash;             // Pre-modulo hash value
    struct timeval lastts;          // Timestamp of last packet
    
    // End of flow header
    
    uint32_t timeout_policy;        // Timeout in seconds
    FlowStateType flow_state;       // FLOW_STATE_NEW, ESTABLISHED, CLOSED
    uint32_t tenant_id;
    
    uint32_t probing_parser_toserver_alproto_masks;
    uint32_t probing_parser_toclient_alproto_masks;
    
    uint32_t flags;                 // FLOW_* flags
    uint16_t file_flags;            // File tracking flags
    
    uint16_t protodetect_dp;        // Destination port for protocol detection
    int64_t parent_id;              // For FTP and similar
    
    SCMutex m;                      // Lock (FLOWLOCK_MUTEX) or SCRWLock r
    
    void *protoctx;                 // Protocol-specific context (TcpSession for TCP)
    uint8_t protomap;               // Protocol to timeout/free function mapping
    
    uint8_t flow_end_flags;         // End-of-flow flags
    
    AppProto alproto;               // Application layer protocol
    AppProto alproto_ts;            // toserver alproto
    AppProto alproto_tc;            // toclient alproto
    AppProto alproto_orig;          // Original protocol before upgrade (STARTTLS)
    AppProto alproto_expect;        // Expected protocol in upgrade
    
    uint32_t de_ctx_version;        // Detection engine context version
    
    uint8_t min_ttl_toserver, max_ttl_toserver;
    uint8_t min_ttl_toclient, max_ttl_toclient;
    
    AppLayerParserState *alparser;  // Application layer parser state
    void *alstate;                  // Application layer state
    
    const struct SigGroupHead_ *sgh_toclient;
    const struct SigGroupHead_ *sgh_toserver;
    
    GenericVar *flowvar;            // Flow variables
    struct FlowBucket_ *fb;         // Parent bucket
    
    struct timeval startts;         // Flow start timestamp
    
    uint32_t todstpktcnt;           // Packets to destination
    uint32_t tosrcpktcnt;           // Packets to source
    uint64_t todstbytecnt;          // Bytes to destination
    uint64_t tosrcbytecnt;          // Bytes to source
} Flow;
```

### 2.2 Flow Lookup via FlowGetFlowFromHash()

**Location:** `/src/flow-hash.c` (lines 731-838)

**Function Signature:**
```c
Flow *FlowGetFlowFromHash(ThreadVars *tv, FlowLookupStruct *fls, Packet *p, Flow **dest)
```

**Parameters:**
- `tv` - Thread variables
- `fls` - Flow lookup struct (contains spare queue, dtv, work queue)
- `p` - Packet to look up flow for
- `dest` - Output: pointer to receive the found/created flow

**Returns:**
- Locked Flow pointer or NULL on error

**Algorithm:**

```
1. Calculate hash = p->flow_hash % flow_config.hash_size
2. Get FlowBucket *fb = &flow_hash[hash]
3. Lock bucket (FBLOCK_LOCK)
4. If bucket empty:
      - Allocate new flow (FlowGetNew)
      - Initialize (FlowInit)
      - Set fb->head = new_flow
      - Return locked flow
5. Else iterate through chain:
      - For each flow in chain:
         - Check if timed out: Remove to work queue
         - Check if matches packet (FlowCompare)
         - If match found: Return locked flow
      - If no match found: Allocate new, add to head of chain
6. Unlock bucket
7. Return flow with reference incremented
```

**Key Implementation Details:**

```c
Flow *FlowGetFlowFromHash(ThreadVars *tv, FlowLookupStruct *fls, Packet *p, Flow **dest)
{
    Flow *f = NULL;

    const uint32_t hash = p->flow_hash;
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FromHashLockBucket(fb);

    if (fb->head == NULL) {
        // Bucket empty - create new flow
        f = FlowGetNew(tv, fls, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }
        fb->head = f;
        FlowInit(f, p);
        f->flow_hash = hash;
        f->fb = fb;
        FlowUpdateState(f, FLOW_STATE_NEW);
        FlowReference(dest, f);
        FBLOCK_UNLOCK(fb);
        return f;
    }

    // Bucket has flows - search for match
    const bool emerg = (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) != 0;
    Flow *prev_f = NULL;
    f = fb->head;
    
    do {
        Flow *next_f = NULL;
        
        // Check timeout
        if (FlowIsTimedOut(f, (uint32_t)p->ts.tv_sec, emerg)) {
            FromHashLockTO(f);
            if (likely(f->use_cnt == 0)) {
                next_f = f->next;
                MoveToWorkQueue(tv, fls, fb, f, prev_f);  // Evict
                FLOWLOCK_UNLOCK(f);
                goto flow_removed;
            }
            FLOWLOCK_UNLOCK(f);
        }
        // Check if flow matches packet tuple
        else if (FlowCompare(f, p) != 0) {
            FromHashLockCMP(f);
            // Check for TCP session reuse
            if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
                Flow *new_f = TcpReuseReplace(tv, fls, fb, f, hash, p);
                if (likely(f->use_cnt == 0)) {
                    if (prev_f == NULL) prev_f = new_f;
                    MoveToWorkQueue(tv, fls, fb, f, prev_f);
                }
                FLOWLOCK_UNLOCK(f);
                if (new_f == NULL) {
                    FBLOCK_UNLOCK(fb);
                    return NULL;
                }
                f = new_f;
            }
            FlowReference(dest, f);
            FBLOCK_UNLOCK(fb);
            return f;  // Return WITH flow lock held
        }
        
        prev_f = f;
        next_f = f->next;

flow_removed:
        if (next_f == NULL) {
            // No matching flow in chain - create new
            f = FlowGetNew(tv, fls, p);
            if (f == NULL) {
                FBLOCK_UNLOCK(fb);
                return NULL;
            }
            f->next = fb->head;
            fb->head = f;
            FlowInit(f, p);
            f->flow_hash = hash;
            f->fb = fb;
            FlowUpdateState(f, FLOW_STATE_NEW);
            FlowReference(dest, f);
            FBLOCK_UNLOCK(fb);
            return f;
        }
        f = next_f;
    } while (f != NULL);

    return NULL;
}
```

### 2.3 Flow Lookup Parameters

**Required packet fields before calling FlowGetFlowFromHash():**

```c
p->flow_hash  // Pre-calculated hash (set by decoder via FlowSetupPacket)
p->src        // Source address
p->dst        // Destination address
p->sp         // Source port (TCP/UDP) or ICMP type
p->dp         // Destination port (TCP/UDP) or ICMP code
p->proto      // Protocol number (IPPROTO_*)
p->recursion_level  // Tunnel depth
p->vlan_id[2]       // VLAN IDs
p->ts         // Packet timestamp (for timeout checking)
```

### 2.4 Flow Initialization - Essential Fields

**FlowInit() sets these critical fields:**

```c
// Address and port fields - already populated from packet
f->src = p->src;
f->dst = p->dst;
f->sp = p->sp;
f->dp = p->dp;
f->proto = p->proto;
f->recursion_level = p->recursion_level;

// Initial state
f->flow_state = FLOW_STATE_NEW;
f->timeout_policy = appropriate_timeout_for_proto;
f->lastts = p->ts;
f->startts = p->ts;

// Reference counter starts at 1 (the packet holding it)
f->use_cnt = 1;

// No protocol-specific context yet
f->protoctx = NULL;  // Set later by stream engine or app layer

// Flags
f->flags = 0;
if (PKT_IS_IPV4(p)) f->flags |= FLOW_IPV4;
else if (PKT_IS_IPV6(p)) f->flags |= FLOW_IPV6;

// Direction based on first packet
f->flags |= (PKT_IS_TOSERVER(p) ? FLOW_TO_DST_SEEN : FLOW_TO_SRC_SEEN);
```

### 2.5 Flow Timeout Handling

**Flow Timeout Configuration:** `/src/flow.c` (lines 695-720)

```c
#define FLOW_DEFAULT_NEW_TIMEOUT        30
#define FLOW_DEFAULT_EST_TIMEOUT        3600
#define FLOW_DEFAULT_CLOSED_TIMEOUT     120
#define FLOW_DEFAULT_BYPASSED_TIMEOUT   600

#define FLOW_DEFAULT_EMERG_NEW_TIMEOUT      10
#define FLOW_DEFAULT_EMERG_EST_TIMEOUT      300
#define FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT   20

typedef struct FlowProtoTimeout_ {
    uint32_t new_timeout;           // TCP_NONE, TCP_SYN_* states
    uint32_t est_timeout;           // TCP_ESTABLISHED
    uint32_t closed_timeout;        // TCP_CLOSED, TCP_TIME_WAIT
    uint32_t bypassed_timeout;      // Bypassed flows
} FlowProtoTimeout;
```

**Timeout Checking in FlowGetFlowFromHash():**

```c
// Calculate if flow is timed out
const bool timedout = (fb_nextts < (uint32_t)p->ts.tv_sec && 
                       FlowIsTimedOut(f, (uint32_t)p->ts.tv_sec, emerg));

if (timedout) {
    // Move to eviction queue for later cleanup
    MoveToWorkQueue(tv, fls, fb, f, prev_f);
}
```

**Emergency Mode:**
- When memory pressure detected, emergency timeouts (much shorter) activate
- Normal: new=30s, est=3600s
- Emergency: new=10s, est=300s

### 2.6 Flow Reference Counting

```c
// Increment reference count
static inline void FlowIncrUsecnt(Flow *f)
{
    if (f == NULL) return;
    f->use_cnt++;
}

// Decrement reference count
static inline void FlowDecrUsecnt(Flow *f)
{
    if (f == NULL) return;
    f->use_cnt--;
}

// Reference (used when assigning to packet->flow)
static inline void FlowReference(Flow **d, Flow *f)
{
    if (likely(f != NULL)) {
        FlowIncrUsecnt(f);
        *d = f;
    }
}

// Dereference
static inline void FlowDeReference(Flow **d)
{
    if (likely(*d != NULL)) {
        FlowDecrUsecnt(*d);
        *d = NULL;
    }
}
```

---

## 3. TCP STREAM REASSEMBLY

### 3.1 TcpSession Structure

**Location:** `/src/stream-tcp-private.h` (lines 260-274)

```c
typedef struct TcpSession_ {
    PoolThreadReserved res;
    uint8_t state:4;                        // Current TCP state (TCP_NONE -> TCP_CLOSED)
    uint8_t pstate:4;                       // Previous state
    uint8_t queue_len;                      // SYN/ACK queue length
    int8_t data_first_seen_dir;             // Direction of first data seen
    
    uint8_t tcp_packet_flags;               // All TCP flags seen in session
    uint16_t flags;                         // Session flags (STREAMTCP_FLAG_*)
    
    uint32_t reassembly_depth;              // Max bytes to reassemble
    
    TcpStream server;                       // Server stream (for received packets)
    TcpStream client;                       // Client stream (for sent packets)
    
    TcpStateQueue *queue;                   // List of SYN/ACK candidates
} TcpSession;
```

**TcpStream Structure (94-129):**

```c
typedef struct TcpStream_ {
    uint16_t flags:12;                      // STREAMTCP_STREAM_FLAG_*
    uint16_t wscale:4;                      // Window scale (0-15)
    
    uint8_t os_policy;                      // Target OS reassembly policy
    uint8_t tcp_flags;                      // Flags seen in this direction
    
    // Sequence tracking
    uint32_t isn;                           // Initial sequence number
    uint32_t next_seq;                      // Next expected sequence number
    uint32_t last_ack;                      // Last ACK'd sequence number
    uint32_t next_win;                      // Next window limit
    uint32_t window;                        // Current window (post-wscale)
    
    // Timestamp tracking
    uint32_t last_ts;                       // Last TCP timestamp value
    uint32_t last_pkt_ts;                   // Packet timestamp for PAWS
    
    // Reassembly
    uint32_t base_seq;                      // Sequence where reassembly starts
    uint32_t app_progress_rel;              // App layer progress
    uint32_t raw_progress_rel;              // Raw reassembly progress
    uint32_t log_progress_rel;              // Streaming logger progress
    
    uint32_t min_inspect_depth;             // Min inspect size
    uint32_t data_required;                 // Data required before app-layer
    
    StreamingBuffer sb;                     // Reassembly buffer
    struct TCPSEG seg_tree;                 // Red-black tree of segments
    uint32_t segs_right_edge;               // Rightmost edge of segments
    
    uint32_t sack_size;                     // Combined SACK range size
    struct TCPSACK sack_tree;               // Red-black tree of SACK records
} TcpStream;
```

### 3.2 StreamTcp() - Main Entry Point

**Location:** `/src/stream-tcp.c` (lines 5264-5303)

```c
TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueueNoLock *pq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    if (!(PKT_IS_TCP(p))) {
        return TM_ECODE_OK;  // Not TCP, skip
    }

    if (p->flow == NULL) {
        StatsIncr(tv, stt->counter_tcp_no_flow);
        return TM_ECODE_OK;  // No flow, skip
    }

    HandleThreadId(tv, p, stt);

    // Checksum validation
    if (!(p->flags & PKT_PSEUDO_STREAM_END)) {
        if (stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION) {
            if (StreamTcpValidateChecksum(p) == 0) {
                StatsIncr(tv, stt->counter_tcp_invalid_checksum);
                return TM_ECODE_OK;  // Invalid checksum, drop
            }
        } else {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        p->flags |= PKT_IGNORE_CHECKSUM;
    }

    AppLayerProfilingReset(stt->ra_ctx->app_tctx);

    // Call packet handler (this does state machine and reassembly)
    (void)StreamTcpPacket(tv, p, stt, pq);

    return TM_ECODE_OK;
}
```

**StreamTcpPacket() continues with:**

1. **State Machine Processing:**
   - Calls StreamTcpStateDispatch() based on current TCP state
   - Handles SYN, SYN-ACK, ACK, FIN, RST, data packets
   - Updates stream pointers (next_seq, last_ack, window)
   - Tracks TCP flags and options

2. **Segment Storage:**
   - Stores segments in TcpStream::seg_tree (red-black tree)
   - Indexed by sequence number
   - Data stored in StreamingBuffer (sb)

3. **Reassembly:**
   - Triggers when stream has data and is established
   - Segments reordered and gaps filled
   - App layer gets reassembled data

4. **Detection:**
   - Calls AppLayerProtoDetect for protocol detection
   - Routes to protocol parsers (HTTP, TLS, etc.)

### 3.3 TCP Session Initialization

**TcpSession Allocation:** From PoolThread (stream-tcp.c:5349-5362)

```c
stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
if (stt->ra_ctx == NULL)
    SCReturnInt(TM_ECODE_FAILED);

SCMutexLock(&ssn_pool_mutex);
if (ssn_pool == NULL) {
    // Create new pool
    ssn_pool = PoolThreadInit(1,           // 1 thread
            0,                              // unlimited max
            stream_config.prealloc_sessions, // prealloc
            sizeof(TcpSession),
            StreamTcpSessionPoolAlloc,      // alloc function
            StreamTcpSessionPoolInit,       // init function
            NULL,
            StreamTcpSessionPoolCleanup,    // cleanup function
            NULL);
    stt->ssn_pool_id = 0;
} else {
    // Expand existing pool for new thread
    stt->ssn_pool_id = PoolThreadExpand(ssn_pool);
}
SCMutexUnlock(&ssn_pool_mutex);
```

**Session Created When:**
- First packet of new flow that is TCP
- Or when SYN received in midstream mode

### 3.4 Segment Storage and Reassembly

**Segment Structure:** (stream-tcp-private.h:61-67)

```c
typedef struct TcpSegment {
    PoolThreadReserved res;
    uint16_t payload_len;           // Actual payload size
    uint32_t seq;                   // Sequence number
    RB_ENTRY(TcpSegment) rb;        // Red-black tree linkage
    StreamingBufferSegment sbseg;   // Link to data in buffer
} TcpSegment;
```

**Red-Black Tree Organization:**
- Segments sorted by sequence number
- Allows O(log n) lookup
- Enables efficient gap detection
- Duplicate sequences handled (smaller first)

**Reassembly Buffer:**
```c
StreamingBuffer sb;  // Manages data storage
                     // Circular buffer with watermarks
                     // Supports partial reads
```

### 3.5 When Stream Reassembly Triggers

**Reassembly occurs when:**

1. **Stream is ESTABLISHED** - At least SYN-SYN-ACK-ACK handshake complete
2. **Data packets received** - Payload_len > 0
3. **Segments in-order or with gaps** - Reassembler tries to fill
4. **App layer requests data** - Via StreamReassembleRaw()
5. **Detection needs stream data** - Detection engine calls reassembly

**Not reassembled:**
- Stream with STREAMTCP_STREAM_FLAG_NOREASSEMBLY set
- Depth reached (STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
- Application layer detection disabled

### 3.6 StreamTcpThreadInit() - Per-Thread Initialization

**Location:** `/src/stream-tcp.c` (lines 5305-5370)

```c
TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    
    // Allocate thread-specific TCP state
    StreamTcpThread *stt = SCMalloc(sizeof(StreamTcpThread));
    if (unlikely(stt == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(stt, 0, sizeof(StreamTcpThread));
    stt->ssn_pool_id = -1;

    *data = (void *)stt;

    // Register counters for statistics
    stt->counter_tcp_sessions = StatsRegisterCounter("tcp.sessions", tv);
    stt->counter_tcp_ssn_memcap = StatsRegisterCounter("tcp.ssn_memcap_drop", tv);
    stt->counter_tcp_pseudo = StatsRegisterCounter("tcp.pseudo", tv);
    stt->counter_tcp_pseudo_failed = StatsRegisterCounter("tcp.pseudo_failed", tv);
    stt->counter_tcp_invalid_checksum = StatsRegisterCounter("tcp.invalid_checksum", tv);
    stt->counter_tcp_no_flow = StatsRegisterCounter("tcp.no_flow", tv);
    stt->counter_tcp_syn = StatsRegisterCounter("tcp.syn", tv);
    stt->counter_tcp_synack = StatsRegisterCounter("tcp.synack", tv);
    stt->counter_tcp_rst = StatsRegisterCounter("tcp.rst", tv);
    stt->counter_tcp_midstream_pickups = StatsRegisterCounter("tcp.midstream_pickups", tv);
    stt->counter_tcp_wrong_thread = StatsRegisterCounter("tcp.pkt_on_wrong_thread", tv);

    // Initialize reassembly context
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
    if (stt->ra_ctx == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    // Register reassembly-specific counters
    stt->ra_ctx->counter_tcp_segment_memcap = StatsRegisterCounter("tcp.segment_memcap_drop", tv);
    stt->ra_ctx->counter_tcp_stream_depth = StatsRegisterCounter("tcp.stream_depth_reached", tv);
    stt->ra_ctx->counter_tcp_reass_gap = StatsRegisterCounter("tcp.reassembly_gap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap = StatsRegisterCounter("tcp.overlap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap_diff_data = StatsRegisterCounter("tcp.overlap_diff_data", tv);
    stt->ra_ctx->counter_tcp_reass_data_normal_fail = StatsRegisterCounter("tcp.insert_data_normal_fail", tv);
    stt->ra_ctx->counter_tcp_reass_data_overlap_fail = StatsRegisterCounter("tcp.insert_data_overlap_fail", tv);
    stt->ra_ctx->counter_tcp_reass_list_fail = StatsRegisterCounter("tcp.insert_list_fail", tv);

    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p",
                stt, stt->ra_ctx);

    // Initialize or expand TCP session pool
    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool == NULL) {
        ssn_pool = PoolThreadInit(1,
                0,
                stream_config.prealloc_sessions,
                sizeof(TcpSession),
                StreamTcpSessionPoolAlloc,
                StreamTcpSessionPoolInit, NULL,
                StreamTcpSessionPoolCleanup, NULL);
        stt->ssn_pool_id = 0;
        SCLogDebug("pool size %d, thread ssn_pool_id %d", 
                   PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    } else {
        stt->ssn_pool_id = PoolThreadExpand(ssn_pool);
        SCLogDebug("pool size %d, thread ssn_pool_id %d", 
                   PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    }
    SCMutexUnlock(&ssn_pool_mutex);
    
    if (stt->ssn_pool_id < 0 || ssn_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, 
                   "failed to setup/expand stream session pool");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
```

---

## 4. INITIALIZATION REQUIREMENTS

### 4.1 Global Flow Initialization: FlowInitConfig()

**Location:** `/src/flow.c` (lines 518-645)

**Must be called once at engine startup:**

```c
void FlowInitConfig(char quiet)
{
    SCLogDebug("initializing flow engine...");

    memset(&flow_config, 0, sizeof(flow_config));
    SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(flow_memuse);
    SC_ATOMIC_INIT(flow_prune_idx);
    SC_ATOMIC_INIT(flow_config.memcap);
    FlowQueueInit(&flow_recycle_q);

    // Set defaults
    flow_config.hash_rand = (uint32_t)RandomGet();  // Random seed for hash
    flow_config.hash_size = FLOW_DEFAULT_HASHSIZE;  // 65536
    flow_config.prealloc = FLOW_DEFAULT_PREALLOC;   // 10000
    SC_ATOMIC_SET(flow_config.memcap, FLOW_DEFAULT_MEMCAP);  // 32 MB

    // Parse configuration from suricata.yaml if available
    // Set flow.memcap, flow.hash-size, flow.prealloc
    // Load from config file or use defaults

    // Allocate hash table
    uint64_t hash_size = flow_config.hash_size * sizeof(FlowBucket);
    flow_hash = SCMallocAligned(flow_config.hash_size * sizeof(FlowBucket), CLS);
    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));

    // Initialize each bucket
    for (uint32_t i = 0; i < flow_config.hash_size; i++) {
        FBLOCK_INIT(&flow_hash[i]);
        SC_ATOMIC_INIT(flow_hash[i].next_ts);
    }

    // Initialize spare pool
    FlowSparePoolInit();
    
    // Initialize protocol timeouts
    FlowInitFlowProto();

    return;
}
```

**Default Configuration:**

```c
#define FLOW_DEFAULT_HASHSIZE    65536
#define FLOW_DEFAULT_MEMCAP      (32 * 1024 * 1024)  // 32 MB
#define FLOW_DEFAULT_PREALLOC    10000
```

### 4.2 Global Stream TCP Initialization: StreamTcpInitConfig()

**Location:** `/src/stream-tcp.c` (lines 368-650)

**Must be called once at engine startup:**

```c
void StreamTcpInitConfig(char quiet)
{
    SCLogDebug("Initializing Stream");

    memset(&stream_config, 0, sizeof(stream_config));

    SC_ATOMIC_INIT(stream_config.memcap);
    SC_ATOMIC_INIT(stream_config.reassembly_memcap);

    // Parse configuration
    // Set defaults if not in config:
    
    stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;  // 2048
    SC_ATOMIC_SET(stream_config.memcap, STREAMTCP_DEFAULT_MEMCAP); // 64 MB
    SC_ATOMIC_SET(stream_config.reassembly_memcap, 
                  STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP); // 256 MB
    
    stream_config.reassembly_depth = 0;  // 0 = unlimited
    stream_config.reassembly_toserver_chunk_size = 2560;
    stream_config.reassembly_toclient_chunk_size = 2560;
    
    stream_config.max_synack_queued = 5;
    stream_config.midstream = FALSE;  // Don't pickup mid-stream
    stream_config.async_oneside = FALSE;
    
    // Flags
    stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;  // Validate checksums
    stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;         // Drop invalid packets
    stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;              // Inline mode (if IPS)
    
    // Memcap policies
    stream_config.ssn_memcap_policy = EXCEPTION_POLICY_DEFAULT;
    stream_config.reassembly_memcap_policy = EXCEPTION_POLICY_DEFAULT;
    
    StreamTcpInitMemuse();  // Initialize atomic memuse counter
    
    return;
}
```

**Default Configuration:**

```c
#define STREAMTCP_DEFAULT_PREALLOC              2048
#define STREAMTCP_DEFAULT_MEMCAP                (64 * 1024 * 1024)
#define STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP     (256 * 1024 * 1024)
#define STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED     5

#define STREAMTCP_NEW_TIMEOUT       60
#define STREAMTCP_EST_TIMEOUT       3600
#define STREAMTCP_CLOSED_TIMEOUT    120
```

### 4.3 Per-Thread Initialization

**Decode Thread Vars:** `DecodeThreadVarsAlloc()` - allocates DecodeThreadVars
**TCP Stream Thread:** `StreamTcpThreadInit()` - as shown above

### 4.4 Can We Use Suricata Without Full Engine?

**YES**, but with limitations:

**Supported Stand-Alone:**
- Packet decode (DecodeEthernet, DecodeIPV4, DecodeTCP, etc.)
- Flow management (FlowGetFlowFromHash, flow lifecycle)
- TCP stream tracking (state machine, segment storage)
- Reassembly (TcpStream, reassembly buffers)

**Cannot Use Without Full Engine:**
- Protocol detection (requires app-layer infrastructure)
- Rule detection/matching (requires detection engine)
- Logging and output (requires output framework)
- Statistics/counters (uses global stats infrastructure)

**Minimal Initialization for Standalone:**

```c
// Initialize flow system
FlowInitConfig(TRUE);  // quiet=TRUE, no config file

// Initialize stream TCP
StreamTcpInitConfig(TRUE);

// Initialize thread-local data
DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
StreamTcpThreadInit(tv, NULL, (void**)&stt);

// Now ready to process packets
DecodeEthernet(tv, dtv, pkt, data, len);
```

---

## 5. MINIMAL WORKING EXAMPLE

### 5.1 Complete Initialization Sequence

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode.h"
#include "flow.h"
#include "stream-tcp.h"

int main() {
    // 1. Initialize logging (minimal)
    // SCLogSetLogFp(stdout);
    
    // 2. Initialize random number generator
    // SeedRandom();
    
    // 3. Initialize threading (minimal)
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    tv.id = 1;
    tv.name = "PacketWorker";
    
    // 4. Initialize flow system GLOBALLY (once)
    FlowInitConfig(TRUE);  // quiet mode
    
    // 5. Initialize stream TCP GLOBALLY (once)
    StreamTcpInitConfig(TRUE);
    StreamTcpInitMemuse();
    
    // 6. Initialize thread-local decode variables
    DecodeThreadVars dtv;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    
    // 7. Initialize thread-local stream TCP variables
    StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
    StreamTcpThreadInit(&tv, NULL, (void**)&stt);
    
    // 8. Now ready to process packets
    return 0;
}
```

### 5.2 Packet Processing Flow

```c
// Simplified packet processing pipeline
void process_packet(const uint8_t *pkt_data, uint32_t pkt_len) {
    // 1. Allocate packet structure
    Packet *p = PacketGetFromAlloc();
    if (p == NULL) {
        fprintf(stderr, "Failed to allocate packet\n");
        return;
    }
    
    // 2. Initialize basic fields
    gettimeofday(&p->ts, NULL);
    p->datalink = LINKTYPE_ETHERNET;
    p->pkt_src = PKT_SRC_WIRE;
    p->pktlen = pkt_len;
    
    // Copy packet data (DPDK or custom buffer)
    memcpy(GET_PKT_DIRECT_DATA(p), pkt_data, pkt_len);
    
    // 3. DECODE: Ethernet -> IP -> TCP/UDP
    if (DecodeEthernet(&tv, &dtv, p, pkt_data, pkt_len) == TM_ECODE_FAILED) {
        PacketFree(p);
        return;
    }
    
    // 4. Setup flow hash if IPv4/IPv6 + TCP/UDP
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
            FlowSetupPacket(p);  // Calculates p->flow_hash
        }
    }
    
    // 5. FLOW LOOKUP/CREATE
    Flow *flow = NULL;
    FlowLookupStruct fls;
    memset(&fls, 0, sizeof(fls));
    
    if (p->flags & PKT_WANTS_FLOW) {
        flow = FlowGetFlowFromHash(&tv, &fls, p, &flow);
        if (flow != NULL) {
            p->flow = flow;
            p->flags |= PKT_HAS_FLOW;
        }
    }
    
    // 6. TCP STREAM PROCESSING (if TCP)
    if (flow != NULL && PKT_IS_TCP(p)) {
        StreamTcp(&tv, p, stt, NULL);  // NULL = no pseudo packet queue
    }
    
    // 7. Cleanup
    if (p->flow != NULL) {
        FlowDeReference(&p->flow);
    }
    PacketFree(p);
}
```

### 5.3 Minimal Configuration

```c
// Minimal non-config initialization
typedef struct MinimalConfig {
    uint64_t flow_memcap;
    uint32_t flow_hash_size;
    uint64_t stream_memcap;
    uint64_t stream_reassembly_memcap;
} MinimalConfig;

// Apply custom config before calling Init functions
MinimalConfig cfg = {
    .flow_memcap = 32 * 1024 * 1024,        // 32 MB
    .flow_hash_size = 65536,                 // 64K buckets
    .stream_memcap = 64 * 1024 * 1024,       // 64 MB
    .stream_reassembly_memcap = 256 * 1024 * 1024  // 256 MB
};

// Apply before init:
// flow_config.memcap = cfg.flow_memcap;
// flow_config.hash_size = cfg.flow_hash_size;
// stream_config.memcap = cfg.stream_memcap;
// stream_config.reassembly_memcap = cfg.stream_reassembly_memcap;
```

### 5.4 Memory Pool Management

**TCP Session Pool (auto-managed):**
- Pre-allocates 2048 sessions per thread
- Grows dynamically if needed
- Returns to pool on flow timeout
- Locked by ssn_pool_mutex for expansion

**Segment Pool (auto-managed via StreamingBuffer):**
- Allocates from PoolThread
- Tracks memuse vs memcap
- Drops segments when memcap exceeded
- Clears on flow timeout

### 5.5 Complete Minimal Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "suricata-common.h"
#include "decode.h"
#include "flow.h"
#include "stream-tcp.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Initialize
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    tv.id = 1;
    tv.name = "Worker-1";

    DecodeThreadVars dtv;
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
    memset(stt, 0, sizeof(StreamTcpThread));

    // Global init
    FlowInitConfig(TRUE);
    StreamTcpInitConfig(TRUE);
    StreamTcpInitMemuse();
    StreamTcpThreadInit(&tv, NULL, (void**)&stt);

    // Open PCAP
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr hdr;
    const uint8_t *pkt_data;
    uint64_t pkt_count = 0;

    // Process packets
    while ((pkt_data = pcap_next(handle, &hdr)) != NULL) {
        pkt_count++;

        Packet *p = PacketGetFromAlloc();
        if (p == NULL) continue;

        p->ts.tv_sec = hdr.ts_sec;
        p->ts.tv_usec = hdr.ts_usec;
        p->datalink = LINKTYPE_ETHERNET;
        p->pkt_src = PKT_SRC_WIRE;
        p->pktlen = hdr.len;

        memcpy(GET_PKT_DIRECT_DATA(p), pkt_data, hdr.len);

        // Decode
        DecodeEthernet(&tv, &dtv, p, pkt_data, hdr.len);

        // Flow setup and lookup
        if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
            if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
                FlowSetupPacket(p);
                
                FlowLookupStruct fls;
                memset(&fls, 0, sizeof(fls));
                p->flow = FlowGetFlowFromHash(&tv, &fls, p, &p->flow);
                
                if (p->flow != NULL && PKT_IS_TCP(p)) {
                    StreamTcp(&tv, p, stt, NULL);
                }
            }
        }

        // Cleanup
        PACKET_RECYCLE(p);
        PacketFreeOrRelease(p);

        if (pkt_count % 1000 == 0) {
            printf("Processed %lu packets\n", pkt_count);
        }
    }

    printf("Total packets: %lu\n", pkt_count);

    // Cleanup
    pcap_close(handle);
    StreamTcpThreadDeinit(&tv, stt);
    free(stt);
    FlowShutdown();

    return 0;
}
```

---

## SUMMARY TABLE

| Component | Key Files | Init Function | Per-Thread Init | State Structure |
|-----------|-----------|---------------|-----------------|-----------------|
| **Decode** | decode.c, decode-ethernet.c | - | DecodeThreadVarsAlloc | DecodeThreadVars |
| **Flow** | flow.c, flow-hash.c | FlowInitConfig | - | Flow, FlowBucket |
| **TCP Stream** | stream-tcp.c, stream-tcp-private.h | StreamTcpInitConfig | StreamTcpThreadInit | TcpSession, TcpStream |
| **Reassembly** | stream-tcp-reassemble.c | StreamTcpInitConfig | StreamTcpReassembleInitThreadCtx | StreamingBuffer |

---

**Document Generated:** 2025
**Suricata Version:** 6.0.10
**Purpose:** DPDK-Based NIDS Implementation Reference

