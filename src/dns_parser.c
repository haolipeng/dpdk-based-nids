/*
 * NetDefender - DNS Protocol Parser Implementation
 *
 * This module implements DNS query and response parsing.
 */

#include "dns_parser.h"
#include "flow.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_DNS_PARSER RTE_LOGTYPE_USER6

/* DNS header size */
#define DNS_HEADER_SIZE 12

/* Maximum domain name length */
#define DNS_MAX_NAME_LEN 255

/* Maximum label length */
#define DNS_MAX_LABEL_LEN 63

/* Suspicious TLDs */
static const char *suspicious_tlds[] = {
    ".xyz", ".top", ".club", ".work", ".click", ".country", ".stream",
    ".download", ".loan", ".win", ".bid", ".gq", ".ml", ".cf", ".tk",
    NULL
};

/* Helper macros for DNS header parsing */
#define DNS_GET_ID(data)        (ntohs(*(uint16_t*)(data)))
#define DNS_GET_FLAGS(data)     (ntohs(*(uint16_t*)((data) + 2)))
#define DNS_GET_QDCOUNT(data)   (ntohs(*(uint16_t*)((data) + 4)))
#define DNS_GET_ANCOUNT(data)   (ntohs(*(uint16_t*)((data) + 6)))
#define DNS_GET_NSCOUNT(data)   (ntohs(*(uint16_t*)((data) + 8)))
#define DNS_GET_ARCOUNT(data)   (ntohs(*(uint16_t*)((data) + 10)))

const char *dns_type_to_string(dns_type_t type)
{
    switch (type) {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA:   return "SOA";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        case DNS_TYPE_AAAA:  return "AAAA";
        case DNS_TYPE_SRV:   return "SRV";
        case DNS_TYPE_OPT:   return "OPT";
        case DNS_TYPE_ANY:   return "ANY";
        default:             return "UNKNOWN";
    }
}

const char *dns_rcode_to_string(dns_rcode_t rcode)
{
    switch (rcode) {
        case DNS_RCODE_NOERROR:  return "NOERROR";
        case DNS_RCODE_FORMERR:  return "FORMERR";
        case DNS_RCODE_SERVFAIL: return "SERVFAIL";
        case DNS_RCODE_NXDOMAIN: return "NXDOMAIN";
        case DNS_RCODE_NOTIMP:   return "NOTIMP";
        case DNS_RCODE_REFUSED:  return "REFUSED";
        default:                 return "UNKNOWN";
    }
}

/**
 * @brief Parse DNS name (with compression support)
 */
static int parse_dns_name(const uint8_t *packet, uint32_t packet_len,
                          const uint8_t *ptr, char *name_out, uint16_t *name_len_out)
{
    const uint8_t *p = ptr;
    const uint8_t *packet_end = packet + packet_len;
    char *out = name_out;
    int consumed = 0;
    int jumps = 0;
    const int max_jumps = 10;  /* Prevent infinite loops */
    bool jumped = false;

    *name_len_out = 0;

    while (p < packet_end) {
        uint8_t len = *p;

        /* Check for compression pointer */
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= packet_end) {
                return -1;
            }

            /* Get pointer offset */
            uint16_t offset = ((len & 0x3F) << 8) | *(p + 1);
            if (offset >= packet_len) {
                return -1;
            }

            if (!jumped) {
                consumed = (p - ptr) + 2;
                jumped = true;
            }

            /* Follow pointer */
            p = packet + offset;
            jumps++;

            if (jumps > max_jumps) {
                return -1;  /* Too many jumps */
            }
            continue;
        }

        /* Check for end of name */
        if (len == 0) {
            if (!jumped) {
                consumed = (p - ptr) + 1;
            }
            *out = '\0';
            *name_len_out = out - name_out;
            return consumed;
        }

        /* Check label length */
        if (len > DNS_MAX_LABEL_LEN) {
            return -1;
        }

        /* Check bounds */
        if (p + 1 + len > packet_end) {
            return -1;
        }

        /* Add dot separator (except for first label) */
        if (out != name_out) {
            *out++ = '.';
        }

        /* Copy label */
        p++;
        for (int i = 0; i < len; i++) {
            if (!isprint(*p) && *p != '-' && *p != '_') {
                *out++ = '?';  /* Replace non-printable */
            } else {
                *out++ = *p;
            }
            p++;
        }

        if (out - name_out > DNS_MAX_NAME_LEN - 1) {
            return -1;  /* Name too long */
        }
    }

    return -1;  /* Incomplete name */
}

/**
 * @brief Free DNS question list
 */
static void free_questions(dns_question_t *q)
{
    while (q) {
        dns_question_t *next = q->next;
        if (q->qname) rte_free(q->qname);
        rte_free(q);
        q = next;
    }
}

/**
 * @brief Free DNS resource record list
 */
static void free_rrs(dns_rr_t *rr)
{
    while (rr) {
        dns_rr_t *next = rr->next;
        if (rr->name) rte_free(rr->name);
        if (rr->rdata) rte_free(rr->rdata);
        if (rr->type == DNS_TYPE_CNAME || rr->type == DNS_TYPE_NS ||
            rr->type == DNS_TYPE_PTR) {
            if (rr->parsed.domain) rte_free(rr->parsed.domain);
        } else if (rr->type == DNS_TYPE_MX) {
            if (rr->parsed.mx.exchange) rte_free(rr->parsed.mx.exchange);
        }
        rte_free(rr);
        rr = next;
    }
}

/**
 * @brief Free DNS transaction
 */
static void free_transaction(dns_transaction_t *tx)
{
    if (!tx) return;
    free_questions(tx->questions);
    free_rrs(tx->answers);
    free_rrs(tx->authority);
    free_rrs(tx->additional);
    rte_free(tx);
}

/**
 * @brief Parse DNS question section
 */
static int parse_dns_question(const uint8_t *packet, uint32_t packet_len,
                              const uint8_t *ptr, dns_question_t **q_out)
{
    char name[DNS_MAX_NAME_LEN + 1];
    uint16_t name_len;

    /* Parse QNAME */
    int consumed = parse_dns_name(packet, packet_len, ptr, name, &name_len);
    if (consumed < 0) {
        return -1;
    }

    ptr += consumed;

    /* Check for QTYPE and QCLASS */
    if (ptr + 4 > packet + packet_len) {
        return -1;
    }

    uint16_t qtype = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    uint16_t qclass = ntohs(*(uint16_t*)ptr);
    ptr += 2;

    /* Allocate question */
    dns_question_t *q = rte_zmalloc("dns_question", sizeof(dns_question_t), 0);
    if (!q) {
        return -1;
    }

    q->qname = rte_malloc("dns_qname", name_len + 1, 0);
    if (!q->qname) {
        rte_free(q);
        return -1;
    }

    memcpy(q->qname, name, name_len + 1);
    q->qname_len = name_len;
    q->qtype = qtype;
    q->qclass = qclass;

    *q_out = q;
    return consumed + 4;
}

/**
 * @brief Parse DNS resource record
 */
static int parse_dns_rr(const uint8_t *packet, uint32_t packet_len,
                        const uint8_t *ptr, dns_rr_t **rr_out)
{
    char name[DNS_MAX_NAME_LEN + 1];
    uint16_t name_len;

    /* Parse NAME */
    int consumed = parse_dns_name(packet, packet_len, ptr, name, &name_len);
    if (consumed < 0) {
        return -1;
    }

    ptr += consumed;

    /* Check for TYPE, CLASS, TTL, RDLENGTH */
    if (ptr + 10 > packet + packet_len) {
        return -1;
    }

    uint16_t type = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    uint16_t rr_class = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    uint32_t ttl = ntohl(*(uint32_t*)ptr);
    ptr += 4;
    uint16_t rdlength = ntohs(*(uint16_t*)ptr);
    ptr += 2;

    /* Check RDATA bounds */
    if (ptr + rdlength > packet + packet_len) {
        return -1;
    }

    /* Allocate RR */
    dns_rr_t *rr = rte_zmalloc("dns_rr", sizeof(dns_rr_t), 0);
    if (!rr) {
        return -1;
    }

    rr->name = rte_malloc("dns_rr_name", name_len + 1, 0);
    if (!rr->name) {
        rte_free(rr);
        return -1;
    }

    memcpy(rr->name, name, name_len + 1);
    rr->name_len = name_len;
    rr->type = type;
    rr->rr_class = rr_class;
    rr->ttl = ttl;
    rr->rdlength = rdlength;

    /* Copy RDATA */
    if (rdlength > 0) {
        rr->rdata = rte_malloc("dns_rdata", rdlength, 0);
        if (!rr->rdata) {
            rte_free(rr->name);
            rte_free(rr);
            return -1;
        }
        memcpy(rr->rdata, ptr, rdlength);

        /* Parse common record types */
        if (type == DNS_TYPE_A && rdlength == 4) {
            memcpy(rr->parsed.a.addr, ptr, 4);
        } else if (type == DNS_TYPE_AAAA && rdlength == 16) {
            memcpy(rr->parsed.aaaa.addr, ptr, 16);
        } else if (type == DNS_TYPE_CNAME || type == DNS_TYPE_NS ||
                   type == DNS_TYPE_PTR) {
            char domain[DNS_MAX_NAME_LEN + 1];
            uint16_t domain_len;
            if (parse_dns_name(packet, packet_len, ptr, domain, &domain_len) > 0) {
                rr->parsed.domain = rte_malloc("dns_domain", domain_len + 1, 0);
                if (rr->parsed.domain) {
                    memcpy(rr->parsed.domain, domain, domain_len + 1);
                }
            }
        } else if (type == DNS_TYPE_MX && rdlength >= 2) {
            rr->parsed.mx.preference = ntohs(*(uint16_t*)ptr);
            char exchange[DNS_MAX_NAME_LEN + 1];
            uint16_t exchange_len;
            if (parse_dns_name(packet, packet_len, ptr + 2, exchange, &exchange_len) > 0) {
                rr->parsed.mx.exchange = rte_malloc("dns_mx", exchange_len + 1, 0);
                if (rr->parsed.mx.exchange) {
                    memcpy(rr->parsed.mx.exchange, exchange, exchange_len + 1);
                }
            }
        }
    }

    *rr_out = rr;
    return consumed + 10 + rdlength;
}

dns_conn_t *dns_parser_init(struct flow *flow)
{
    dns_conn_t *conn = rte_zmalloc("dns_conn", sizeof(dns_conn_t), 0);
    if (!conn) {
        return NULL;
    }
    return conn;
}

void dns_parser_free(dns_conn_t *conn)
{
    if (!conn) return;

    /* Free transactions */
    dns_transaction_t *tx = conn->transactions;
    while (tx) {
        dns_transaction_t *next = tx->next;
        free_transaction(tx);
        tx = next;
    }

    rte_free(conn);
}

int dns_parser_parse(dns_conn_t *conn, const uint8_t *data, uint32_t len,
                     bool is_tcp)
{
    if (!conn || !data) {
        return -1;
    }

    const uint8_t *packet = data;
    uint32_t packet_len = len;

    /* Handle DNS over TCP (has 2-byte length prefix) */
    if (is_tcp) {
        if (len < 2) {
            return -1;
        }
        uint16_t dns_len = ntohs(*(uint16_t*)data);
        packet = data + 2;
        packet_len = len - 2;

        if (packet_len < dns_len) {
            return -1;  /* Incomplete */
        }
        packet_len = dns_len;
    }

    /* Check minimum size */
    if (packet_len < DNS_HEADER_SIZE) {
        conn->parse_errors++;
        return -1;
    }

    /* Parse DNS header */
    uint16_t txid = DNS_GET_ID(packet);
    uint16_t flags = DNS_GET_FLAGS(packet);
    uint16_t qdcount = DNS_GET_QDCOUNT(packet);
    uint16_t ancount = DNS_GET_ANCOUNT(packet);
    uint16_t nscount = DNS_GET_NSCOUNT(packet);
    uint16_t arcount = DNS_GET_ARCOUNT(packet);

    bool is_response = (flags & DNS_FLAG_QR) != 0;
    uint8_t opcode = (flags >> 11) & 0x0F;
    uint8_t rcode = flags & 0x0F;

    /* Create transaction */
    dns_transaction_t *tx = rte_zmalloc("dns_tx", sizeof(dns_transaction_t), 0);
    if (!tx) {
        conn->parse_errors++;
        return -1;
    }

    tx->txid = txid;
    tx->is_response = is_response;
    tx->opcode = opcode;
    tx->rcode = rcode;
    tx->recursion_desired = (flags & DNS_FLAG_RD) != 0;
    tx->authoritative = (flags & DNS_FLAG_AA) != 0;
    tx->truncated = (flags & DNS_FLAG_TC) != 0;
    tx->recursion_available = (flags & DNS_FLAG_RA) != 0;
    tx->qdcount = qdcount;
    tx->ancount = ancount;
    tx->nscount = nscount;
    tx->arcount = arcount;

    if (is_response) {
        tx->response_len = packet_len;
        conn->responses_parsed++;
        if (rcode == DNS_RCODE_NXDOMAIN) {
            conn->nxdomain_count++;
        }
    } else {
        tx->query_len = packet_len;
        conn->queries_parsed++;
    }

    const uint8_t *ptr = packet + DNS_HEADER_SIZE;

    /* Parse questions */
    dns_question_t **q_tail = &tx->questions;
    for (int i = 0; i < qdcount && i < 10; i++) {  /* Limit to 10 questions */
        dns_question_t *q = NULL;
        int consumed = parse_dns_question(packet, packet_len, ptr, &q);
        if (consumed < 0) {
            free_transaction(tx);
            conn->parse_errors++;
            return -1;
        }

        *q_tail = q;
        q_tail = &q->next;
        ptr += consumed;

        /* Check for suspicious domain */
        if (q && q->qname) {
            if (dns_is_suspicious_domain(q->qname)) {
                conn->suspicious_tld = true;
            }
            double entropy = dns_calculate_entropy(q->qname);
            if (entropy > 4.5) {
                conn->high_entropy_domain = true;
            }
        }
    }

    /* Parse answers (if response) */
    if (is_response) {
        dns_rr_t **rr_tail = &tx->answers;
        for (int i = 0; i < ancount && i < 20; i++) {  /* Limit to 20 answers */
            dns_rr_t *rr = NULL;
            int consumed = parse_dns_rr(packet, packet_len, ptr, &rr);
            if (consumed < 0) {
                break;  /* Don't fail on answer parse errors */
            }

            *rr_tail = rr;
            rr_tail = &rr->next;
            ptr += consumed;

            /* Update statistics */
            if (rr) {
                switch (rr->type) {
                    case DNS_TYPE_A:     conn->a_records++; break;
                    case DNS_TYPE_AAAA:  conn->aaaa_records++; break;
                    case DNS_TYPE_CNAME: conn->cname_records++; break;
                    case DNS_TYPE_TXT:   conn->txt_records++; break;
                    default: break;
                }
            }
        }

        /* Parse authority section (simplified) */
        rr_tail = &tx->authority;
        for (int i = 0; i < nscount && i < 10; i++) {
            dns_rr_t *rr = NULL;
            int consumed = parse_dns_rr(packet, packet_len, ptr, &rr);
            if (consumed < 0) break;
            *rr_tail = rr;
            rr_tail = &rr->next;
            ptr += consumed;
        }

        /* Parse additional section (simplified) */
        rr_tail = &tx->additional;
        for (int i = 0; i < arcount && i < 10; i++) {
            dns_rr_t *rr = NULL;
            int consumed = parse_dns_rr(packet, packet_len, ptr, &rr);
            if (consumed < 0) break;
            *rr_tail = rr;
            rr_tail = &rr->next;
            ptr += consumed;
        }
    }

    /* Add transaction to list */
    tx->next = conn->transactions;
    conn->transactions = tx;
    conn->tx_count++;

    /* Enhanced logging with query details */
    if (!is_response && tx->questions) {
        dns_question_t *q = tx->questions;
        RTE_LOG(INFO, DNS_PARSER,
                "DNS Query: %s type=%s class=%u txid=%u\n",
                q->qname ? q->qname : "<null>",
                dns_type_to_string(q->qtype),
                q->qclass,
                txid);
    } else if (is_response) {
        const char *first_qname = (tx->questions && tx->questions->qname) ? tx->questions->qname : "<null>";
        RTE_LOG(INFO, DNS_PARSER,
                "DNS Response: %s rcode=%s answers=%u txid=%u\n",
                first_qname,
                dns_rcode_to_string(tx->rcode),
                ancount,
                txid);
    }

    return 0;
}

dns_transaction_t *dns_get_latest_transaction(dns_conn_t *conn)
{
    return conn ? conn->transactions : NULL;
}

dns_transaction_t *dns_find_transaction(dns_conn_t *conn, uint16_t txid)
{
    if (!conn) return NULL;

    for (dns_transaction_t *tx = conn->transactions; tx != NULL; tx = tx->next) {
        if (tx->txid == txid) {
            return tx;
        }
    }
    return NULL;
}

bool dns_is_suspicious_domain(const char *domain)
{
    if (!domain) return false;

    /* Check for suspicious TLDs */
    for (int i = 0; suspicious_tlds[i] != NULL; i++) {
        if (strstr(domain, suspicious_tlds[i]) != NULL) {
            return true;
        }
    }

    /* Check for excessive subdomains */
    int dot_count = 0;
    for (const char *p = domain; *p; p++) {
        if (*p == '.') dot_count++;
    }
    if (dot_count > 5) {
        return true;
    }

    /* Check for non-printable characters */
    for (const char *p = domain; *p; p++) {
        if (!isprint(*p) && *p != '.') {
            return true;
        }
    }

    return false;
}

double dns_calculate_entropy(const char *domain)
{
    if (!domain) return 0.0;

    int freq[256] = {0};
    int len = 0;

    /* Count character frequencies */
    for (const char *p = domain; *p; p++) {
        if (*p != '.') {  /* Ignore dots */
            freq[(unsigned char)*p]++;
            len++;
        }
    }

    if (len == 0) return 0.0;

    /* Calculate Shannon entropy */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

void dns_get_stats(const dns_conn_t *conn, char *buf, size_t buf_size)
{
    if (!conn || !buf || buf_size == 0) {
        return;
    }

    snprintf(buf, buf_size,
             "DNS Stats: tx=%u q=%lu r=%lu err=%lu nxd=%lu A=%lu AAAA=%lu CNAME=%lu%s%s%s",
             conn->tx_count,
             conn->queries_parsed,
             conn->responses_parsed,
             conn->parse_errors,
             conn->nxdomain_count,
             conn->a_records,
             conn->aaaa_records,
             conn->cname_records,
             conn->suspicious_tld ? " [SUSPICIOUS_TLD]" : "",
             conn->dga_suspected ? " [DGA]" : "",
             conn->high_entropy_domain ? " [HIGH_ENTROPY]" : "");
}
