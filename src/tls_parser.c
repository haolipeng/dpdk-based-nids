/*
 * NetDefender - TLS/SSL Protocol Parser Implementation
 *
 * This module parses TLS handshake messages and extracts security-relevant information.
 */

#define _GNU_SOURCE
#define OPENSSL_API_COMPAT 0x10100000L  /* Allow deprecated MD5 API */

#include "tls_parser.h"
#include "flow.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

/* For MD5 hash (JA3) */
#include <openssl/md5.h>

#define RTE_LOGTYPE_TLS_PARSER RTE_LOGTYPE_USER8

/* Cipher suite database (common ciphers) */
static const tls_cipher_suite_t cipher_suite_db[] = {
    {0x0000, "TLS_NULL_WITH_NULL_NULL", true},
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5", true},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA", true},
    {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", true},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", false},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", false},
    {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", false},
    {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", false},
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", false},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", false},
    {0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", true},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", false},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", false},
    {0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", true},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", false},
    {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", false},
    {0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", false},
    {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", false},
    {0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", false},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false},
    {0x1301, "TLS_AES_128_GCM_SHA256", false},
    {0x1302, "TLS_AES_256_GCM_SHA384", false},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256", false},
    {0, NULL, false}
};

const char *tls_version_to_string(tls_version_t version)
{
    switch (version) {
        case TLS_VERSION_SSL30:   return "SSL 3.0";
        case TLS_VERSION_TLS10:   return "TLS 1.0";
        case TLS_VERSION_TLS11:   return "TLS 1.1";
        case TLS_VERSION_TLS12:   return "TLS 1.2";
        case TLS_VERSION_TLS13:   return "TLS 1.3";
        default:                  return "Unknown";
    }
}

const char *tls_cipher_suite_to_string(uint16_t cipher_suite)
{
    for (int i = 0; cipher_suite_db[i].name != NULL; i++) {
        if (cipher_suite_db[i].value == cipher_suite) {
            return cipher_suite_db[i].name;
        }
    }
    return "UNKNOWN_CIPHER";
}

bool tls_is_weak_cipher(uint16_t cipher_suite)
{
    for (int i = 0; cipher_suite_db[i].name != NULL; i++) {
        if (cipher_suite_db[i].value == cipher_suite) {
            return cipher_suite_db[i].is_weak;
        }
    }
    /* Unknown cipher, consider potentially weak */
    return false;
}

/* Calculate JA3 fingerprint hash */
static void calculate_ja3_hash(const char *ja3_string, uint8_t *hash_out)
{
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, ja3_string, strlen(ja3_string));
    MD5_Final(hash_out, &md5_ctx);
}

/* Build JA3 string from ClientHello */
static void build_ja3_string(tls_client_hello_t *ch, char *ja3_str, size_t ja3_len)
{
    char buf[TLS_MAX_JA3_STR];
    int offset = 0;

    /* Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats */

    /* 1. SSL Version */
    offset += snprintf(buf + offset, sizeof(buf) - offset, "%u,", ch->version);

    /* 2. Cipher suites */
    for (uint16_t i = 0; i < ch->cipher_suite_count; i++) {
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%u", ch->cipher_suites[i]);
        if (i < ch->cipher_suite_count - 1) {
            offset += snprintf(buf + offset, sizeof(buf) - offset, "-");
        }
    }
    offset += snprintf(buf + offset, sizeof(buf) - offset, ",");

    /* 3. Extensions */
    for (uint16_t i = 0; i < ch->extension_count; i++) {
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%u", ch->extensions[i].type);
        if (i < ch->extension_count - 1) {
            offset += snprintf(buf + offset, sizeof(buf) - offset, "-");
        }
    }
    offset += snprintf(buf + offset, sizeof(buf) - offset, ",");

    /* 4. Supported Groups (EllipticCurves) - simplified, would need to parse extension data */
    offset += snprintf(buf + offset, sizeof(buf) - offset, ",");

    /* 5. EC Point Formats - simplified (empty) */
    /* No additional output needed for empty field */

    strncpy(ja3_str, buf, ja3_len - 1);
    ja3_str[ja3_len - 1] = '\0';
}

/* Build JA3S string from ServerHello */
static void build_ja3s_string(tls_server_hello_t *sh, char *ja3s_str, size_t ja3s_len)
{
    char buf[TLS_MAX_JA3_STR];
    int offset = 0;

    /* Format: SSLVersion,Cipher,Extensions */

    /* 1. SSL Version */
    offset += snprintf(buf + offset, sizeof(buf) - offset, "%u,", sh->version);

    /* 2. Cipher suite */
    offset += snprintf(buf + offset, sizeof(buf) - offset, "%u,", sh->cipher_suite);

    /* 3. Extensions */
    for (uint16_t i = 0; i < sh->extension_count; i++) {
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%u", sh->extensions[i].type);
        if (i < sh->extension_count - 1) {
            offset += snprintf(buf + offset, sizeof(buf) - offset, "-");
        }
    }

    strncpy(ja3s_str, buf, ja3s_len - 1);
    ja3s_str[ja3s_len - 1] = '\0';
}

/* Parse SNI extension */
static int parse_sni_extension(const uint8_t *data, uint16_t len, tls_client_hello_t *ch)
{
    if (len < 5) return -1;

    /* SNI list length */
    uint16_t list_len = (data[0] << 8) | data[1];
    if (list_len + 2 > len) return -1;

    const uint8_t *p = data + 2;
    uint16_t remaining = list_len;

    while (remaining >= 3) {
        uint8_t name_type = *p++;
        uint16_t name_len = (p[0] << 8) | p[1];
        p += 2;
        remaining -= 3;

        if (name_len > remaining) break;

        /* Type 0 = hostname */
        if (name_type == 0 && name_len > 0 && name_len < TLS_MAX_SNI_LEN) {
            ch->sni = rte_malloc("tls_sni", name_len + 1, 0);
            if (ch->sni) {
                memcpy(ch->sni, p, name_len);
                ch->sni[name_len] = '\0';
            }
            break;
        }

        p += name_len;
        remaining -= name_len;
    }

    return 0;
}

/* Parse ALPN extension */
static int parse_alpn_extension(const uint8_t *data, uint16_t len, tls_client_hello_t *ch)
{
    if (len < 2) return -1;

    /* ALPN list length */
    uint16_t list_len = (data[0] << 8) | data[1];
    if (list_len + 2 > len) return -1;

    const uint8_t *p = data + 2;
    uint16_t remaining = list_len;

    /* Just extract first protocol for simplicity */
    if (remaining >= 1) {
        uint8_t proto_len = *p++;
        remaining--;

        if (proto_len > 0 && proto_len <= remaining && proto_len < TLS_MAX_ALPN_LEN) {
            ch->alpn = rte_malloc("tls_alpn", proto_len + 1, 0);
            if (ch->alpn) {
                memcpy(ch->alpn, p, proto_len);
                ch->alpn[proto_len] = '\0';
            }
        }
    }

    return 0;
}

/* Parse ClientHello extensions */
static int parse_client_hello_extensions(const uint8_t *data, uint16_t len,
                                          tls_client_hello_t *ch)
{
    const uint8_t *p = data;
    uint16_t remaining = len;

    while (remaining >= 4) {
        uint16_t ext_type = (p[0] << 8) | p[1];
        uint16_t ext_len = (p[2] << 8) | p[3];
        p += 4;
        remaining -= 4;

        if (ext_len > remaining) break;

        /* Store extension */
        if (ch->extension_count < TLS_MAX_EXTENSIONS) {
            tls_extension_t *ext = &ch->extensions[ch->extension_count];
            ext->type = ext_type;
            ext->length = ext_len;
            ext->data = NULL;  /* Don't copy data for now */

            /* Parse specific extensions */
            if (ext_type == TLS_EXT_SERVER_NAME) {
                parse_sni_extension(p, ext_len, ch);
            } else if (ext_type == TLS_EXT_ALPN) {
                parse_alpn_extension(p, ext_len, ch);
            }

            ch->extension_count++;
        }

        p += ext_len;
        remaining -= ext_len;
    }

    return 0;
}

/* Parse ClientHello message */
static int parse_client_hello(tls_conn_t *conn, const uint8_t *data, uint32_t len)
{
    if (len < 38) return -1;  /* Minimum ClientHello size */

    const uint8_t *p = data;

    /* Allocate ClientHello structure */
    tls_client_hello_t *ch = rte_zmalloc("tls_client_hello",
                                          sizeof(tls_client_hello_t), 0);
    if (!ch) return -1;

    /* Protocol version */
    ch->version = (p[0] << 8) | p[1];
    p += 2;

    /* Random (32 bytes) */
    memcpy(ch->random, p, 32);
    p += 32;

    /* Session ID */
    ch->session_id_len = *p++;
    if (ch->session_id_len > 32) {
        rte_free(ch);
        return -1;
    }
    if (ch->session_id_len > 0) {
        memcpy(ch->session_id, p, ch->session_id_len);
        p += ch->session_id_len;
    }

    /* Cipher suites */
    if (p - data + 2 > len) {
        rte_free(ch);
        return -1;
    }
    uint16_t cipher_suites_len = (p[0] << 8) | p[1];
    p += 2;

    if (cipher_suites_len % 2 != 0 || p - data + cipher_suites_len > len) {
        rte_free(ch);
        return -1;
    }

    ch->cipher_suite_count = cipher_suites_len / 2;
    if (ch->cipher_suite_count > TLS_MAX_CIPHER_SUITES) {
        ch->cipher_suite_count = TLS_MAX_CIPHER_SUITES;
    }

    for (uint16_t i = 0; i < ch->cipher_suite_count; i++) {
        ch->cipher_suites[i] = (p[0] << 8) | p[1];
        p += 2;
    }
    if (cipher_suites_len > ch->cipher_suite_count * 2) {
        p += (cipher_suites_len - ch->cipher_suite_count * 2);
    }

    /* Compression methods */
    if (p - data + 1 > len) {
        rte_free(ch);
        return -1;
    }
    uint8_t compression_len = *p++;
    if (p - data + compression_len > len) {
        rte_free(ch);
        return -1;
    }

    ch->compression_method_count = compression_len;
    if (ch->compression_method_count > 16) {
        ch->compression_method_count = 16;
    }
    memcpy(ch->compression_methods, p, ch->compression_method_count);
    p += compression_len;

    /* Extensions */
    if (p - data + 2 <= len) {
        uint16_t extensions_len = (p[0] << 8) | p[1];
        p += 2;

        if (p - data + extensions_len <= len) {
            parse_client_hello_extensions(p, extensions_len, ch);
        }
    }

    /* Build JA3 fingerprint */
    build_ja3_string(ch, ch->ja3_string, sizeof(ch->ja3_string));
    calculate_ja3_hash(ch->ja3_string, ch->ja3_hash);

    conn->client_hello = ch;
    conn->client_hello_seen = true;

    /* Log with JA3 hash */
    char ja3_hash_str[33];
    for (int i = 0; i < 16; i++) {
        snprintf(ja3_hash_str + i * 2, 3, "%02x", ch->ja3_hash[i]);
    }
    RTE_LOG(INFO, TLS_PARSER,
            "TLS ClientHello: version=%s ciphers=%u SNI=%s ALPN=%s JA3=%s\n",
            tls_version_to_string(ch->version),
            ch->cipher_suite_count,
            ch->sni ? ch->sni : "-",
            ch->alpn ? ch->alpn : "-",
            ja3_hash_str);

    return 0;
}

/* Parse ServerHello extensions */
static int parse_server_hello_extensions(const uint8_t *data, uint16_t len,
                                          tls_server_hello_t *sh)
{
    const uint8_t *p = data;
    uint16_t remaining = len;

    while (remaining >= 4) {
        uint16_t ext_type = (p[0] << 8) | p[1];
        uint16_t ext_len = (p[2] << 8) | p[3];
        p += 4;
        remaining -= 4;

        if (ext_len > remaining) break;

        /* Store extension */
        if (sh->extension_count < TLS_MAX_EXTENSIONS) {
            tls_extension_t *ext = &sh->extensions[sh->extension_count];
            ext->type = ext_type;
            ext->length = ext_len;
            ext->data = NULL;

            sh->extension_count++;
        }

        p += ext_len;
        remaining -= ext_len;
    }

    return 0;
}

/* Parse ServerHello message */
static int parse_server_hello(tls_conn_t *conn, const uint8_t *data, uint32_t len)
{
    if (len < 38) return -1;  /* Minimum ServerHello size */

    const uint8_t *p = data;

    /* Allocate ServerHello structure */
    tls_server_hello_t *sh = rte_zmalloc("tls_server_hello",
                                          sizeof(tls_server_hello_t), 0);
    if (!sh) return -1;

    /* Protocol version */
    sh->version = (p[0] << 8) | p[1];
    p += 2;

    /* Random (32 bytes) */
    memcpy(sh->random, p, 32);
    p += 32;

    /* Session ID */
    sh->session_id_len = *p++;
    if (sh->session_id_len > 32) {
        rte_free(sh);
        return -1;
    }
    if (sh->session_id_len > 0) {
        memcpy(sh->session_id, p, sh->session_id_len);
        p += sh->session_id_len;
    }

    /* Cipher suite */
    if (p - data + 2 > len) {
        rte_free(sh);
        return -1;
    }
    sh->cipher_suite = (p[0] << 8) | p[1];
    sh->cipher_suite_name = tls_cipher_suite_to_string(sh->cipher_suite);
    p += 2;

    /* Compression method */
    if (p - data + 1 > len) {
        rte_free(sh);
        return -1;
    }
    sh->compression_method = *p++;

    /* Extensions */
    if (p - data + 2 <= len) {
        uint16_t extensions_len = (p[0] << 8) | p[1];
        p += 2;

        if (p - data + extensions_len <= len) {
            parse_server_hello_extensions(p, extensions_len, sh);
        }
    }

    /* Build JA3S fingerprint */
    build_ja3s_string(sh, sh->ja3s_string, sizeof(sh->ja3s_string));
    calculate_ja3_hash(sh->ja3s_string, sh->ja3s_hash);

    conn->server_hello = sh;
    conn->server_hello_seen = true;
    conn->negotiated_version = sh->version;
    conn->negotiated_cipher = sh->cipher_suite;

    /* Check for weak cipher */
    if (tls_is_weak_cipher(sh->cipher_suite)) {
        conn->weak_cipher = true;
    }

    /* Check for version downgrade (if ClientHello was TLS 1.3 but ServerHello is lower) */
    if (conn->client_hello && conn->client_hello->version >= TLS_VERSION_TLS13 &&
        sh->version < TLS_VERSION_TLS13) {
        conn->version_downgrade = true;
    }

    /* Log with JA3S hash and security warnings */
    char ja3s_hash_str[33];
    for (int i = 0; i < 16; i++) {
        snprintf(ja3s_hash_str + i * 2, 3, "%02x", sh->ja3s_hash[i]);
    }
    RTE_LOG(INFO, TLS_PARSER,
            "TLS ServerHello: version=%s cipher=%s%s%s JA3S=%s\n",
            tls_version_to_string(sh->version),
            sh->cipher_suite_name,
            conn->weak_cipher ? " [WEAK]" : "",
            conn->version_downgrade ? " [DOWNGRADE]" : "",
            ja3s_hash_str);

    return 0;
}

/* Simplified certificate parsing - just extract basic info */
static int parse_certificate(tls_conn_t *conn, const uint8_t *data, uint32_t len,
                              uint8_t direction)
{
    if (len < 3) return -1;

    const uint8_t *p = data;

    /* Total certificates length */
    uint32_t certs_len = (p[0] << 16) | (p[1] << 8) | p[2];
    p += 3;

    if (certs_len > len - 3) return -1;

    /* Parse first certificate only (for simplicity) */
    if (certs_len >= 3) {
        uint32_t cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
        p += 3;

        if (cert_len > 0 && cert_len <= certs_len - 3) {
            /* Allocate certificate structure */
            tls_certificate_t *cert = rte_zmalloc("tls_certificate",
                                                   sizeof(tls_certificate_t), 0);
            if (cert) {
                /* Real certificate parsing would use OpenSSL here */
                /* For now, just mark that we've seen it */

                if (direction == 0) {  /* to-server = client cert */
                    conn->client_cert_chain = cert;
                    conn->client_cert_seen = true;
                } else {  /* to-client = server cert */
                    conn->server_cert_chain = cert;
                    conn->server_cert_seen = true;
                }

                RTE_LOG(DEBUG, TLS_PARSER, "Certificate message parsed: %s certificate\n",
                        direction == 0 ? "client" : "server");
            }
        }
    }

    return 0;
}

/* Parse TLS handshake message */
static int parse_handshake(tls_conn_t *conn, const uint8_t *data, uint32_t len,
                           uint8_t direction)
{
    if (len < 4) return -1;

    uint8_t handshake_type = data[0];
    uint32_t handshake_len = (data[1] << 16) | (data[2] << 8) | data[3];

    if (handshake_len + 4 > len) return -1;

    const uint8_t *handshake_data = data + 4;

    conn->handshakes_parsed++;

    switch (handshake_type) {
        case TLS_HANDSHAKE_CLIENT_HELLO:
            return parse_client_hello(conn, handshake_data, handshake_len);

        case TLS_HANDSHAKE_SERVER_HELLO:
            return parse_server_hello(conn, handshake_data, handshake_len);

        case TLS_HANDSHAKE_CERTIFICATE:
            return parse_certificate(conn, handshake_data, handshake_len, direction);

        case TLS_HANDSHAKE_SERVER_HELLO_DONE:
        case TLS_HANDSHAKE_FINISHED:
            conn->handshake_completed = true;
            break;

        default:
            /* Other handshake types not implemented yet */
            break;
    }

    return handshake_len + 4;
}

/* Parse TLS record */
static int parse_tls_record(tls_conn_t *conn, const uint8_t *data, uint32_t len,
                            uint8_t direction)
{
    if (len < 5) return 0;  /* Need at least TLS record header */

    uint8_t content_type = data[0];
    uint16_t version = (data[1] << 8) | data[2];
    uint16_t record_len = (data[3] << 8) | data[4];

    /* Validate record */
    if (record_len > 16384 || (uint32_t)(record_len + 5) > len) {
        return -1;
    }

    const uint8_t *record_data = data + 5;

    conn->records_parsed++;

    /* Parse based on content type */
    switch (content_type) {
        case TLS_RECORD_HANDSHAKE:
            parse_handshake(conn, record_data, record_len, direction);
            break;

        case TLS_RECORD_APPLICATION_DATA:
            conn->app_data_records++;
            break;

        default:
            /* Other record types (alerts, change cipher spec, etc.) */
            break;
    }

    return record_len + 5;
}

/* Public API */

tls_conn_t *tls_parser_init(struct flow *flow)
{
    tls_conn_t *conn = rte_zmalloc("tls_conn", sizeof(tls_conn_t), 0);
    if (!conn) {
        return NULL;
    }

    conn->flow = flow;
    return conn;
}

void tls_parser_free(tls_conn_t *conn)
{
    if (!conn) return;

    /* Free ClientHello */
    if (conn->client_hello) {
        if (conn->client_hello->sni) rte_free(conn->client_hello->sni);
        if (conn->client_hello->alpn) rte_free(conn->client_hello->alpn);
        rte_free(conn->client_hello);
    }

    /* Free ServerHello */
    if (conn->server_hello) {
        rte_free(conn->server_hello);
    }

    /* Free certificates */
    tls_certificate_t *cert = conn->server_cert_chain;
    while (cert) {
        tls_certificate_t *next = cert->next;
        if (cert->subject) rte_free(cert->subject);
        if (cert->issuer) rte_free(cert->issuer);
        if (cert->serial) rte_free(cert->serial);
        rte_free(cert);
        cert = next;
    }

    cert = conn->client_cert_chain;
    while (cert) {
        tls_certificate_t *next = cert->next;
        if (cert->subject) rte_free(cert->subject);
        if (cert->issuer) rte_free(cert->issuer);
        if (cert->serial) rte_free(cert->serial);
        rte_free(cert);
        cert = next;
    }

    rte_free(conn);
}

int tls_parser_parse(tls_conn_t *conn, const uint8_t *data, uint32_t len,
                     uint8_t direction)
{
    if (!conn || !data || len == 0) {
        return -1;
    }

    uint32_t consumed = 0;

    /* Parse TLS records */
    while (consumed < len) {
        int ret = parse_tls_record(conn, data + consumed, len - consumed, direction);
        if (ret <= 0) {
            break;
        }
        consumed += ret;
    }

    return consumed;
}

void tls_get_stats(tls_conn_t *conn, char *buf, size_t buflen)
{
    if (!conn || !buf) return;

    snprintf(buf, buflen,
             "TLS: records=%lu handshakes=%lu app_data=%lu version=%s cipher=%s%s%s%s",
             conn->records_parsed,
             conn->handshakes_parsed,
             conn->app_data_records,
             conn->negotiated_version ? tls_version_to_string(conn->negotiated_version) : "unknown",
             conn->server_hello ? conn->server_hello->cipher_suite_name : "unknown",
             conn->weak_cipher ? " [WEAK_CIPHER]" : "",
             conn->version_downgrade ? " [VERSION_DOWNGRADE]" : "",
             conn->expired_cert ? " [EXPIRED_CERT]" : "");
}

tls_client_hello_t *tls_get_client_hello(tls_conn_t *conn)
{
    return conn ? conn->client_hello : NULL;
}

tls_server_hello_t *tls_get_server_hello(tls_conn_t *conn)
{
    return conn ? conn->server_hello : NULL;
}

tls_certificate_t *tls_get_server_cert_chain(tls_conn_t *conn)
{
    return conn ? conn->server_cert_chain : NULL;
}
