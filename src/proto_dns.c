/*
 * NetDefender - DNS Protocol Detection
 *
 * Detects DNS traffic using probing parser that validates DNS message structure.
 */

#include "proto_detect.h"
#include "app_proto.h"
#include "flow.h"
#include <rte_log.h>

#define RTE_LOGTYPE_DNS RTE_LOGTYPE_USER4

/* DNS header flags */
#define DNS_FLAG_QR     0x8000  /* Query/Response bit */
#define DNS_FLAG_OPCODE 0x7800  /* Opcode (standard query = 0) */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncation */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */
#define DNS_FLAG_RCODE  0x000F  /* Response code */

/* DNS opcodes */
#define DNS_OPCODE_QUERY    0   /* Standard query */
#define DNS_OPCODE_IQUERY   1   /* Inverse query (obsolete) */
#define DNS_OPCODE_STATUS   2   /* Server status request */
#define DNS_OPCODE_NOTIFY   4   /* Zone change notification */
#define DNS_OPCODE_UPDATE   5   /* Dynamic update */

/**
 * @brief DNS probing parser
 *
 * DNS message format:
 *   Bytes 0-1:    Transaction ID
 *   Bytes 2-3:    Flags
 *   Bytes 4-5:    Question count
 *   Bytes 6-7:    Answer RR count
 *   Bytes 8-9:    Authority RR count
 *   Bytes 10-11:  Additional RR count
 *   Bytes 12+:    Questions and RRs
 */
static app_proto_t dns_probing_parser(struct flow *flow, uint8_t direction,
                                       const uint8_t *data, uint32_t len,
                                       bool *reverse_flow)
{
    /* Need at least 12 bytes for DNS header */
    if (len < 12) {
        return APP_PROTO_UNKNOWN;
    }

    /* Parse DNS header */
    uint16_t flags = (data[2] << 8) | data[3];
    uint16_t qdcount = (data[4] << 8) | data[5];   /* Questions */
    uint16_t ancount = (data[6] << 8) | data[7];   /* Answers */
    uint16_t nscount = (data[8] << 8) | data[9];   /* Authority */
    uint16_t arcount = (data[10] << 8) | data[11]; /* Additional */

    /* Extract fields from flags */
    bool is_response = (flags & DNS_FLAG_QR) != 0;
    uint8_t opcode = (flags & DNS_FLAG_OPCODE) >> 11;
    uint8_t rcode = flags & DNS_FLAG_RCODE;

    /* Validate opcode (must be one of known types) */
    if (opcode > 5) {
        return APP_PROTO_FAILED;
    }

    /* Validate response code (0-15, common ones are 0-5) */
    if (rcode > 15) {
        return APP_PROTO_FAILED;
    }

    /* Queries should have at least 1 question */
    if (!is_response && qdcount == 0) {
        return APP_PROTO_FAILED;
    }

    /* Responses should have at least 1 question or answer */
    if (is_response && qdcount == 0 && ancount == 0) {
        return APP_PROTO_FAILED;
    }

    /* Sanity check: total counts shouldn't be absurdly high */
    uint32_t total_rr = qdcount + ancount + nscount + arcount;
    if (total_rr > 100) {  /* Reasonable limit */
        return APP_PROTO_FAILED;
    }

    /* Additional validation for queries: check question section */
    if (!is_response && len > 12) {
        /* Question section starts at byte 12 */
        uint32_t offset = 12;
        bool valid_qname = false;

        /* Parse QNAME (domain name in label format) */
        while (offset < len) {
            uint8_t label_len = data[offset];

            /* End of QNAME (null label) */
            if (label_len == 0) {
                valid_qname = true;
                offset++;
                break;
            }

            /* Pointer (compression) - starts with 11 in top 2 bits */
            if ((label_len & 0xC0) == 0xC0) {
                valid_qname = true;
                offset += 2;  /* Pointer is 2 bytes */
                break;
            }

            /* Label length should be reasonable (max 63) */
            if (label_len > 63) {
                return APP_PROTO_FAILED;
            }

            /* Move past label */
            offset += 1 + label_len;

            /* Prevent infinite loop */
            if (offset > 255) {  /* Domain names max 255 bytes */
                return APP_PROTO_FAILED;
            }
        }

        /* Check if we have QTYPE and QCLASS after QNAME */
        if (valid_qname && offset + 4 <= len) {
            uint16_t qtype = (data[offset] << 8) | data[offset + 1];
            uint16_t qclass = (data[offset + 2] << 8) | data[offset + 3];

            /* Validate QTYPE (common types: 1-16, 28, 33, 255, etc.) */
            /* We allow any value up to 65535, but check for zero */
            if (qtype == 0) {
                return APP_PROTO_FAILED;
            }

            /* Validate QCLASS (1 = IN (Internet), 3 = CH (Chaos), 4 = HS, 255 = ANY) */
            if (qclass == 0 || (qclass > 4 && qclass != 255)) {
                return APP_PROTO_FAILED;
            }

            /* Valid DNS query */
            return APP_PROTO_DNS;
        }
    }

    /* For responses or short queries, header validation is enough */
    if (is_response || len == 12) {
        return APP_PROTO_DNS;
    }

    /* Not enough information yet */
    return APP_PROTO_UNKNOWN;
}

int proto_detect_register_dns(void)
{
    int ret = 0;

    /* DNS over UDP on port 53 */
    ret = proto_detect_register_prober(
        APP_PROTO_DNS,
        53,                         /* Port 53 */
        12,                         /* Minimum 12 bytes (DNS header) */
        512,                        /* Examine up to 512 bytes (traditional DNS max) */
        PROTO_DETECT_DIR_BOTH,      /* Both directions */
        dns_probing_parser
    );

    /* DNS on any port (for DNS over non-standard ports) */
    ret |= proto_detect_register_prober(
        APP_PROTO_DNS,
        0,                          /* Any port */
        12,                         /* Minimum 12 bytes */
        512,                        /* Examine up to 512 bytes */
        PROTO_DETECT_DIR_BOTH,      /* Both directions */
        dns_probing_parser
    );

    if (ret == 0) {
        RTE_LOG(INFO, DNS, "Registered DNS detection probing parser\n");
    }

    return ret;
}
