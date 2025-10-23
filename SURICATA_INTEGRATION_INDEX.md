# Suricata Integration Documentation Index

This directory contains comprehensive documentation for integrating Suricata 6.0.10 packet processing, flow management, and TCP stream reassembly into a DPDK-based NIDS implementation.

## Documents Overview

### 1. SURICATA_ANALYSIS.md (37 KB)
**Comprehensive deep-dive reference document**

The primary technical document covering all aspects of Suricata integration.

Contents:
- Packet Decode Process (1.1-1.5)
  - DecodeEthernet() function implementation
  - Decode cascade (Ethernet → IP → TCP/UDP)
  - Packet fields populated during decode
  - Setup requirements before calling DecodeEthernet()
  - PKT_STREAM_ESTABLISHED flag explanation

- Flow Management (2.1-2.6)
  - Complete Flow structure definition (355+ fields)
  - FlowGetFlowFromHash() function with full implementation
  - Flow lookup parameters and algorithm
  - Flow initialization and field setup
  - Timeout handling (normal and emergency modes)
  - Reference counting system

- TCP Stream Reassembly (3.1-3.6)
  - TcpSession structure (state, flags, streams)
  - TcpStream structure (sequence tracking, reassembly)
  - StreamTcp() main entry point
  - Segment storage in red-black trees
  - Reassembly trigger conditions
  - StreamTcpThreadInit() per-thread initialization

- Initialization Requirements (4.1-4.4)
  - FlowInitConfig() global initialization with defaults
  - StreamTcpInitConfig() global initialization
  - Per-thread initialization sequence
  - Standalone usage without full Suricata engine

- Minimal Working Example (5.1-5.5)
  - Complete initialization sequence
  - Packet processing flow with code examples
  - Memory pool management
  - Full working program example

**When to use:** When you need comprehensive technical details about any component of the Suricata packet processing pipeline.

### 2. QUICK_REFERENCE.md (11 KB)
**Quick lookup guide for common tasks**

Fast reference for the most commonly needed information.

Contents:
1. Three-stage processing pipeline diagram
2. Critical initialization code snippets
3. Minimal packet processing code
4. Memory configuration values
5. Packet struct key fields (before/after decode)
6. Flow struct key fields and timeout defaults
7. TcpSession and TcpStream key fields
8. Critical flag definitions
9. Hash table design and collision handling
10. TCP state machine diagram
11. Reassembly trigger conditions
12. Error handling patterns
13. Performance optimization notes
14. Linux kernel differences
15. Integration checklist

**When to use:** When you need to quickly find a specific constant, function call, or field name.

## Key Information by Topic

### Decode Process
- **Overview:** SURICATA_ANALYSIS.md - Section 1
- **Quick Start:** QUICK_REFERENCE.md - Sections 1, 3, 5
- **Function Signature:** SURICATA_ANALYSIS.md - 1.1
- **Packet Fields:** QUICK_REFERENCE.md - Section 5

### Flow Management
- **Structure Definition:** SURICATA_ANALYSIS.md - 2.1
- **Lookup Algorithm:** SURICATA_ANALYSIS.md - 2.2 (with 150 lines of implementation)
- **Flow Initialization:** SURICATA_ANALYSIS.md - 2.4
- **Timeout Handling:** QUICK_REFERENCE.md - Section 6, SURICATA_ANALYSIS.md - 2.5
- **Reference Counting:** SURICATA_ANALYSIS.md - 2.6

### TCP Reassembly
- **Session Structure:** QUICK_REFERENCE.md - Section 7, SURICATA_ANALYSIS.md - 3.1
- **Main Entry Point:** SURICATA_ANALYSIS.md - 3.2
- **Segment Storage:** SURICATA_ANALYSIS.md - 3.4
- **Reassembly Triggers:** QUICK_REFERENCE.md - Section 11, SURICATA_ANALYSIS.md - 3.5
- **Thread Init:** SURICATA_ANALYSIS.md - 3.6

### Initialization
- **Global Initialization:** SURICATA_ANALYSIS.md - 4.1, 4.2
- **Per-Thread Init:** QUICK_REFERENCE.md - Section 2
- **Default Values:** QUICK_REFERENCE.md - Section 4, Configuration Constants

### Code Examples
- **Minimal Example:** QUICK_REFERENCE.md - Section 3
- **Full Example:** SURICATA_ANALYSIS.md - 5.5
- **Error Handling:** QUICK_REFERENCE.md - Section 12

## File Locations in Source

All source files referenced are in:
`/home/work/clionProject/dpdk-based-nids/source-references/suricata-6.0.10/src/`

Key files:
- `decode.h` (1340 lines) - Packet structure and decode declarations
- `decode.c` (200+ lines) - Core decode functions
- `decode-ethernet.c` (150 lines) - Ethernet decode implementation
- `flow.h` (726 lines) - Flow structure definition
- `flow.c` (645+ lines) - Flow initialization and management
- `flow-hash.h` (102 lines) - Flow hash table declarations
- `flow-hash.c` (838+ lines) - Flow lookup/creation (FlowGetFlowFromHash at line 731)
- `stream-tcp.h` (205 lines) - Stream TCP declarations
- `stream-tcp.c` (5400+ lines) - TCP stream implementation
- `stream-tcp-private.h` (287 lines) - TcpSession and TcpStream structures

## Usage Patterns

### Pattern 1: Initial Setup (One-Time)
```c
FlowInitConfig(TRUE);
StreamTcpInitConfig(TRUE);
StreamTcpInitMemuse();
```
Reference: SURICATA_ANALYSIS.md - Section 4, QUICK_REFERENCE.md - Section 2

### Pattern 2: Per-Thread Setup
```c
StreamTcpThreadInit(tv, NULL, (void**)&stt);
```
Reference: SURICATA_ANALYSIS.md - 3.6, QUICK_REFERENCE.md - Section 2

### Pattern 3: Packet Processing Loop
```c
DecodeEthernet(tv, &dtv, p, data, len);
FlowSetupPacket(p);
Flow *f = FlowGetFlowFromHash(tv, &fls, p, &p->flow);
if (f && PKT_IS_TCP(p)) StreamTcp(tv, p, stt, NULL);
```
Reference: QUICK_REFERENCE.md - Section 3

### Pattern 4: Memory Configuration
```c
flow_config.memcap = 32 * 1024 * 1024;
stream_config.memcap = 64 * 1024 * 1024;
```
Reference: QUICK_REFERENCE.md - Section 4

## Configuration Constants

All default values documented in:
- QUICK_REFERENCE.md - Configuration Constants section
- SURICATA_ANALYSIS.md - Throughout Section 4

Key values:
- Flow hash size: 65536 buckets
- Flow memcap: 32 MB (minimum)
- Stream memcap: 64 MB
- Reassembly memcap: 256 MB
- Timeout (new): 30-60 seconds
- Timeout (established): 3600 seconds (1 hour)

## Performance Notes

For high-speed DPDK integration:
1. Increase hash_size proportionally to connection count
2. Consider dual-memcap system (flow + reassembly separate)
3. Use per-thread pools to reduce lock contention
4. Monitor emergency mode activation (indicates memory pressure)
5. Profile red-black tree insertion performance for out-of-order segments

See QUICK_REFERENCE.md - Section 13 for details

## Debugging Tips

1. **Check packet decode failures:** Look for PKT_IS_INVALID flag
2. **Flow creation failures:** Usually memcap exceeded (check flow_memuse)
3. **TCP reassembly issues:** Check STREAMTCP_STREAM_FLAG_DEPTH_REACHED
4. **Hash table collisions:** Increase hash_size if bucket chains exceed 3-5 flows
5. **Timeout issues:** Compare lastts with current timestamp

## Integration Checklist

Use QUICK_REFERENCE.md - Section 15 for complete checklist:
- [ ] Global initialization (FlowInitConfig, StreamTcpInitConfig)
- [ ] Per-thread initialization (StreamTcpThreadInit)
- [ ] Packet field setup before decode
- [ ] Flow hash calculation
- [ ] Flow lookup and creation
- [ ] TCP stream processing
- [ ] Memory cleanup
- [ ] Proper shutdown sequence

## Next Steps

1. **Start with QUICK_REFERENCE.md** to understand the overall flow
2. **Review Section 3 (Minimal Code)** to understand the main functions
3. **Consult SURICATA_ANALYSIS.md** for implementation details
4. **Use QUICK_REFERENCE.md Sections 4-7** for memory and field configuration
5. **Reference SURICATA_ANALYSIS.md Section 5** for complete working example

## Version Information

- **Suricata Version:** 6.0.10
- **Documentation Date:** October 2025
- **Source Location:** `/home/work/clionProject/dpdk-based-nids/source-references/suricata-6.0.10/src/`
- **Analysis Methodology:** Code-level thorough exploration of all key files

## Contact & References

For questions about specific implementations:
- Look up function in SURICATA_ANALYSIS.md (contains line numbers)
- Check implementation in corresponding .c file at listed line number
- Review related structures in corresponding .h file
- Cross-reference with QUICK_REFERENCE.md for quick answers

---

**Document Index:** 1209 lines of detailed analysis + 11 KB quick reference
**Total Coverage:** Decode, Flow, TCP Stream, Reassembly, Initialization
**Status:** Complete and ready for DPDK integration
