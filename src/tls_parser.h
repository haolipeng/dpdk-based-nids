/*
 * NetDefender - TLS/SSL Protocol Parser
 *
 * This module parses TLS handshake messages and extracts security-relevant information.
 */

#ifndef __TLS_PARSER_H__
#define __TLS_PARSER_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Forward declarations */
struct flow;

/* TLS versions */
typedef enum {
    TLS_VERSION_UNKNOWN = 0,
    TLS_VERSION_SSL30   = 0x0300,
    TLS_VERSION_TLS10   = 0x0301,
    TLS_VERSION_TLS11   = 0x0302,
    TLS_VERSION_TLS12   = 0x0303,
    TLS_VERSION_TLS13   = 0x0304,
} tls_version_t;

/* TLS record types */
typedef enum {
    TLS_RECORD_CHANGE_CIPHER_SPEC = 20,
    TLS_RECORD_ALERT              = 21,
    TLS_RECORD_HANDSHAKE          = 22,
    TLS_RECORD_APPLICATION_DATA   = 23,
    TLS_RECORD_HEARTBEAT          = 24,
} tls_record_type_t;

/* TLS handshake types */
typedef enum {
    TLS_HANDSHAKE_HELLO_REQUEST       = 0,
    TLS_HANDSHAKE_CLIENT_HELLO        = 1,
    TLS_HANDSHAKE_SERVER_HELLO        = 2,
    TLS_HANDSHAKE_NEW_SESSION_TICKET  = 4,
    TLS_HANDSHAKE_END_OF_EARLY_DATA   = 5,
    TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 8,
    TLS_HANDSHAKE_CERTIFICATE         = 11,
    TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    TLS_HANDSHAKE_SERVER_HELLO_DONE   = 14,
    TLS_HANDSHAKE_CERTIFICATE_VERIFY  = 15,
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    TLS_HANDSHAKE_FINISHED            = 20,
} tls_handshake_type_t;

/* TLS extension types */
typedef enum {
    TLS_EXT_SERVER_NAME              = 0,
    TLS_EXT_MAX_FRAGMENT_LENGTH      = 1,
    TLS_EXT_STATUS_REQUEST           = 5,
    TLS_EXT_SUPPORTED_GROUPS         = 10,
    TLS_EXT_EC_POINT_FORMATS         = 11,
    TLS_EXT_SIGNATURE_ALGORITHMS     = 13,
    TLS_EXT_ALPN                     = 16,
    TLS_EXT_ENCRYPT_THEN_MAC         = 22,
    TLS_EXT_EXTENDED_MASTER_SECRET   = 23,
    TLS_EXT_SESSION_TICKET           = 35,
    TLS_EXT_SUPPORTED_VERSIONS       = 43,
    TLS_EXT_PSK_KEY_EXCHANGE_MODES   = 45,
    TLS_EXT_KEY_SHARE                = 51,
} tls_extension_type_t;

/* Maximum sizes */
#define TLS_MAX_CIPHER_SUITES  128
#define TLS_MAX_EXTENSIONS     32
#define TLS_MAX_SNI_LEN        256
#define TLS_MAX_ALPN_LEN       32
#define TLS_MAX_JA3_STR        512
#define TLS_MAX_CERT_SUBJECT   256
#define TLS_MAX_CERT_ISSUER    256
#define TLS_MAX_CERT_SERIAL    64
#define TLS_MAX_CERT_FINGERPRINT 64
#define TLS_JA3_HASH_LEN       32  /* MD5 hash */

/* TLS cipher suite info */
typedef struct tls_cipher_suite {
    uint16_t value;
    const char *name;
    bool is_weak;  /* Weak/deprecated cipher */
} tls_cipher_suite_t;

/* TLS extension info */
typedef struct tls_extension {
    uint16_t type;
    uint16_t length;
    uint8_t *data;

    /* Parsed extension data */
    union {
        struct {
            char *hostname;  /* SNI hostname */
        } sni;
        struct {
            char *protocols[8];  /* ALPN protocols */
            uint8_t count;
        } alpn;
    } parsed;
} tls_extension_t;

/* X.509 Certificate information */
typedef struct tls_certificate {
    char *subject;       /* Certificate subject DN */
    char *issuer;        /* Certificate issuer DN */
    char *serial;        /* Serial number (hex string) */
    time_t not_before;   /* Valid from */
    time_t not_after;    /* Valid until */

    /* Certificate fingerprints */
    uint8_t sha1_fingerprint[20];
    uint8_t sha256_fingerprint[32];

    /* Certificate flags */
    bool is_self_signed;
    bool is_expired;
    bool is_not_yet_valid;

    /* Next certificate in chain */
    struct tls_certificate *next;
} tls_certificate_t;

/* ClientHello message */
typedef struct tls_client_hello {
    tls_version_t version;
    uint8_t random[32];

    /* Session ID */
    uint8_t session_id_len;
    uint8_t session_id[32];

    /* Cipher suites */
    uint16_t cipher_suites[TLS_MAX_CIPHER_SUITES];
    uint16_t cipher_suite_count;

    /* Compression methods */
    uint8_t compression_methods[16];
    uint8_t compression_method_count;

    /* Extensions */
    tls_extension_t extensions[TLS_MAX_EXTENSIONS];
    uint16_t extension_count;

    /* Extracted info */
    char *sni;           /* Server Name Indication */
    char *alpn;          /* Application-Layer Protocol Negotiation */

    /* JA3 fingerprint */
    char ja3_string[TLS_MAX_JA3_STR];   /* JA3 input string */
    uint8_t ja3_hash[TLS_JA3_HASH_LEN]; /* JA3 MD5 hash */
} tls_client_hello_t;

/* ServerHello message */
typedef struct tls_server_hello {
    tls_version_t version;
    uint8_t random[32];

    /* Session ID */
    uint8_t session_id_len;
    uint8_t session_id[32];

    /* Chosen cipher suite */
    uint16_t cipher_suite;
    const char *cipher_suite_name;

    /* Compression method */
    uint8_t compression_method;

    /* Extensions */
    tls_extension_t extensions[TLS_MAX_EXTENSIONS];
    uint16_t extension_count;

    /* JA3S fingerprint */
    char ja3s_string[TLS_MAX_JA3_STR];   /* JA3S input string */
    uint8_t ja3s_hash[TLS_JA3_HASH_LEN]; /* JA3S MD5 hash */
} tls_server_hello_t;

/* TLS connection state */
typedef struct tls_conn {
    struct flow *flow;

    /* Handshake messages */
    tls_client_hello_t *client_hello;
    tls_server_hello_t *server_hello;
    tls_certificate_t *server_cert_chain;
    tls_certificate_t *client_cert_chain;

    /* Negotiated parameters */
    tls_version_t negotiated_version;
    uint16_t negotiated_cipher;

    /* Flags */
    bool client_hello_seen;
    bool server_hello_seen;
    bool server_cert_seen;
    bool client_cert_seen;
    bool handshake_completed;

    /* Anomaly flags */
    bool version_downgrade;      /* TLS version downgrade detected */
    bool weak_cipher;            /* Weak cipher suite detected */
    bool self_signed_cert;       /* Self-signed certificate */
    bool expired_cert;           /* Expired certificate */
    bool invalid_cert_chain;     /* Invalid certificate chain */

    /* Statistics */
    uint64_t records_parsed;
    uint64_t handshakes_parsed;
    uint64_t app_data_records;
} tls_conn_t;

/* Function prototypes */

/**
 * @brief Initialize TLS parser for a flow
 * @param flow Flow structure
 * @return TLS connection structure or NULL on error
 */
tls_conn_t *tls_parser_init(struct flow *flow);

/**
 * @brief Free TLS parser resources
 * @param conn TLS connection structure
 */
void tls_parser_free(tls_conn_t *conn);

/**
 * @brief Parse TLS data
 * @param conn TLS connection structure
 * @param data Input data
 * @param len Data length
 * @param direction 0=to-server, 1=to-client
 * @return Number of bytes consumed, or -1 on error
 */
int tls_parser_parse(tls_conn_t *conn, const uint8_t *data, uint32_t len,
                     uint8_t direction);

/**
 * @brief Get TLS version string
 * @param version TLS version enum
 * @return Version string
 */
const char *tls_version_to_string(tls_version_t version);

/**
 * @brief Get cipher suite name
 * @param cipher_suite Cipher suite value
 * @return Cipher suite name
 */
const char *tls_cipher_suite_to_string(uint16_t cipher_suite);

/**
 * @brief Check if cipher suite is weak/deprecated
 * @param cipher_suite Cipher suite value
 * @return true if weak
 */
bool tls_is_weak_cipher(uint16_t cipher_suite);

/**
 * @brief Get TLS connection statistics
 * @param conn TLS connection structure
 * @param buf Output buffer
 * @param buflen Buffer length
 */
void tls_get_stats(tls_conn_t *conn, char *buf, size_t buflen);

/**
 * @brief Get ClientHello from TLS connection
 * @param conn TLS connection structure
 * @return ClientHello structure or NULL
 */
tls_client_hello_t *tls_get_client_hello(tls_conn_t *conn);

/**
 * @brief Get ServerHello from TLS connection
 * @param conn TLS connection structure
 * @return ServerHello structure or NULL
 */
tls_server_hello_t *tls_get_server_hello(tls_conn_t *conn);

/**
 * @brief Get server certificate chain
 * @param conn TLS connection structure
 * @return Certificate chain or NULL
 */
tls_certificate_t *tls_get_server_cert_chain(tls_conn_t *conn);

#endif /* __TLS_PARSER_H__ */
