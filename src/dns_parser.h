/*
 * NetDefender - DNS Protocol Parser
 *
 * This module provides DNS query and response parsing.
 * Extracts domain names, record types, answers, and detects anomalies.
 */

#ifndef __DNS_PARSER_H__
#define __DNS_PARSER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations */
struct flow;

/* DNS record types (most common ones) */
typedef enum {
    DNS_TYPE_A = 1,         /* IPv4 address */
    DNS_TYPE_NS = 2,        /* Name server */
    DNS_TYPE_CNAME = 5,     /* Canonical name */
    DNS_TYPE_SOA = 6,       /* Start of authority */
    DNS_TYPE_PTR = 12,      /* Pointer */
    DNS_TYPE_MX = 15,       /* Mail exchange */
    DNS_TYPE_TXT = 16,      /* Text */
    DNS_TYPE_AAAA = 28,     /* IPv6 address */
    DNS_TYPE_SRV = 33,      /* Service */
    DNS_TYPE_OPT = 41,      /* EDNS */
    DNS_TYPE_ANY = 255,     /* Any */
} dns_type_t;

/* DNS class */
typedef enum {
    DNS_CLASS_IN = 1,       /* Internet */
    DNS_CLASS_CS = 2,       /* CSNET (obsolete) */
    DNS_CLASS_CH = 3,       /* CHAOS */
    DNS_CLASS_HS = 4,       /* Hesiod */
    DNS_CLASS_ANY = 255,    /* Any */
} dns_class_t;

/* DNS response codes */
typedef enum {
    DNS_RCODE_NOERROR = 0,  /* No error */
    DNS_RCODE_FORMERR = 1,  /* Format error */
    DNS_RCODE_SERVFAIL = 2, /* Server failure */
    DNS_RCODE_NXDOMAIN = 3, /* Non-existent domain */
    DNS_RCODE_NOTIMP = 4,   /* Not implemented */
    DNS_RCODE_REFUSED = 5,  /* Refused */
} dns_rcode_t;

/* DNS opcode */
typedef enum {
    DNS_OPCODE_QUERY = 0,   /* Standard query */
    DNS_OPCODE_IQUERY = 1,  /* Inverse query (obsolete) */
    DNS_OPCODE_STATUS = 2,  /* Server status */
    DNS_OPCODE_NOTIFY = 4,  /* Notify */
    DNS_OPCODE_UPDATE = 5,  /* Update */
} dns_opcode_t;

/* DNS flags */
#define DNS_FLAG_QR     0x8000  /* Query/Response */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncated */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */
#define DNS_FLAG_Z      0x0040  /* Reserved */
#define DNS_FLAG_AD     0x0020  /* Authenticated Data */
#define DNS_FLAG_CD     0x0010  /* Checking Disabled */

/* DNS question */
typedef struct dns_question {
    char *qname;                    /* Query name (domain) */
    uint16_t qname_len;             /* Name length */
    dns_type_t qtype;               /* Question type */
    dns_class_t qclass;             /* Question class */
    struct dns_question *next;      /* Next question */
} dns_question_t;

/* DNS resource record */
typedef struct dns_rr {
    char *name;                     /* Domain name */
    uint16_t name_len;              /* Name length */
    dns_type_t type;                /* Record type */
    dns_class_t rr_class;           /* Record class */
    uint32_t ttl;                   /* Time to live */
    uint16_t rdlength;              /* Data length */
    uint8_t *rdata;                 /* Record data */

    /* Parsed data for common types */
    union {
        char *domain;               /* For CNAME, NS, PTR */
        struct {
            uint8_t addr[4];        /* For A record */
        } a;
        struct {
            uint8_t addr[16];       /* For AAAA record */
        } aaaa;
        struct {
            uint16_t preference;
            char *exchange;
        } mx;
    } parsed;

    struct dns_rr *next;            /* Next RR */
} dns_rr_t;

/* DNS transaction (query + response) */
typedef struct dns_transaction {
    uint16_t txid;                  /* Transaction ID */

    /* Query */
    bool is_response;               /* True if response */
    dns_opcode_t opcode;            /* Operation code */
    bool recursion_desired;         /* RD flag */
    uint16_t qdcount;               /* Question count */
    dns_question_t *questions;      /* Questions */

    /* Response */
    dns_rcode_t rcode;              /* Response code */
    bool authoritative;             /* AA flag */
    bool truncated;                 /* TC flag */
    bool recursion_available;       /* RA flag */
    uint16_t ancount;               /* Answer count */
    uint16_t nscount;               /* Authority count */
    uint16_t arcount;               /* Additional count */
    dns_rr_t *answers;              /* Answer RRs */
    dns_rr_t *authority;            /* Authority RRs */
    dns_rr_t *additional;           /* Additional RRs */

    /* Timestamps */
    uint64_t query_ts;              /* Query timestamp */
    uint64_t response_ts;           /* Response timestamp */

    /* Statistics */
    uint32_t query_len;             /* Query packet length */
    uint32_t response_len;          /* Response packet length */

    struct dns_transaction *next;   /* Next transaction */
} dns_transaction_t;

/* DNS connection state (per flow) */
typedef struct dns_conn {
    dns_transaction_t *transactions;    /* Transaction list */
    uint32_t tx_count;                  /* Total transactions */

    /* Statistics */
    uint64_t queries_parsed;
    uint64_t responses_parsed;
    uint64_t parse_errors;
    uint64_t nxdomain_count;            /* NXDOMAIN responses */
    uint64_t a_records;                 /* A record count */
    uint64_t aaaa_records;              /* AAAA record count */
    uint64_t cname_records;             /* CNAME count */
    uint64_t txt_records;               /* TXT count */

    /* Anomaly detection flags */
    bool suspicious_tld;                /* Suspicious TLD detected */
    bool dga_suspected;                 /* DGA pattern suspected */
    bool high_entropy_domain;           /* High entropy domain name */
    bool excessive_subdomains;          /* Too many subdomains */
} dns_conn_t;

/**
 * @brief Initialize DNS parser for a flow
 *
 * @param flow Flow to attach DNS parser to
 * @return DNS connection state, or NULL on error
 */
dns_conn_t *dns_parser_init(struct flow *flow);

/**
 * @brief Free DNS parser state
 *
 * @param conn DNS connection state to free
 */
void dns_parser_free(dns_conn_t *conn);

/**
 * @brief Parse DNS packet (query or response)
 *
 * DNS can be over UDP (single packet) or TCP (with 2-byte length prefix).
 * This function handles both cases automatically.
 *
 * @param conn DNS connection state
 * @param data DNS packet data
 * @param len Data length
 * @param is_tcp True if DNS over TCP
 * @return 0 on success, -1 on error
 */
int dns_parser_parse(dns_conn_t *conn, const uint8_t *data, uint32_t len,
                     bool is_tcp);

/**
 * @brief Get latest DNS transaction
 *
 * @param conn DNS connection state
 * @return Latest transaction, or NULL if none
 */
dns_transaction_t *dns_get_latest_transaction(dns_conn_t *conn);

/**
 * @brief Find transaction by ID
 *
 * @param conn DNS connection state
 * @param txid Transaction ID
 * @return Transaction, or NULL if not found
 */
dns_transaction_t *dns_find_transaction(dns_conn_t *conn, uint16_t txid);

/**
 * @brief Convert DNS type to string
 *
 * @param type DNS type enum
 * @return Type string (e.g., "A", "AAAA")
 */
const char *dns_type_to_string(dns_type_t type);

/**
 * @brief Convert DNS rcode to string
 *
 * @param rcode Response code
 * @return Rcode string (e.g., "NOERROR", "NXDOMAIN")
 */
const char *dns_rcode_to_string(dns_rcode_t rcode);

/**
 * @brief Check if domain name is suspicious
 *
 * Performs basic heuristic checks for:
 * - Suspicious TLDs
 * - High entropy (possible DGA)
 * - Excessive subdomain levels
 * - Non-printable characters
 *
 * @param domain Domain name to check
 * @return true if suspicious
 */
bool dns_is_suspicious_domain(const char *domain);

/**
 * @brief Calculate domain entropy
 *
 * @param domain Domain name
 * @return Entropy value (0.0 - 8.0, higher = more random)
 */
double dns_calculate_entropy(const char *domain);

/**
 * @brief Get statistics string
 *
 * @param conn DNS connection state
 * @param buf Output buffer
 * @param buf_size Buffer size
 */
void dns_get_stats(const dns_conn_t *conn, char *buf, size_t buf_size);

#endif /* __DNS_PARSER_H__ */
