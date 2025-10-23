/*
 * NetDefender - TLS/SSL Protocol Detection
 *
 * Detects TLS/SSL traffic using probing parser that validates TLS handshake structure.
 */

#include "proto_detect.h"
#include "app_proto.h"
#include "flow.h"
#include <rte_log.h>

#define RTE_LOGTYPE_TLS RTE_LOGTYPE_USER3

/* TLS record types */
#define TLS_RECORD_CHANGE_CIPHER_SPEC   20
#define TLS_RECORD_ALERT                21
#define TLS_RECORD_HANDSHAKE            22
#define TLS_RECORD_APPLICATION_DATA     23
#define TLS_RECORD_HEARTBEAT            24

/* TLS versions */
#define TLS_VERSION_SSL30   0x0300
#define TLS_VERSION_TLS10   0x0301
#define TLS_VERSION_TLS11   0x0302
#define TLS_VERSION_TLS12   0x0303
#define TLS_VERSION_TLS13   0x0304

/* TLS handshake types */
#define TLS_HANDSHAKE_CLIENT_HELLO      1
#define TLS_HANDSHAKE_SERVER_HELLO      2
#define TLS_HANDSHAKE_CERTIFICATE       11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE 14

/**
 * @brief TLS probing parser
 *
 * TLS record format:
 *   Byte 0:       Content Type (20-24)
 *   Bytes 1-2:    Version (0x0300 - 0x0304)
 *   Bytes 3-4:    Length (big-endian, <= 16384)
 *   Bytes 5+:     Payload
 */
static app_proto_t tls_probing_parser(struct flow *flow, uint8_t direction,
                                       const uint8_t *data, uint32_t len,
                                       bool *reverse_flow)
{
    /* Need at least 5 bytes for TLS record header */
    if (len < 5) {
        return APP_PROTO_UNKNOWN;
    }

    uint8_t content_type = data[0];
    uint16_t version = (data[1] << 8) | data[2];
    uint16_t record_len = (data[3] << 8) | data[4];

    /* Validate content type */
    if (content_type < TLS_RECORD_CHANGE_CIPHER_SPEC ||
        content_type > TLS_RECORD_HEARTBEAT) {
        /* Try SSLv2 format (legacy) */
        if ((data[0] & 0x80) && len >= 3) {
            /* SSLv2 ClientHello: first byte has high bit set */
            uint8_t msg_type = data[2];
            if (msg_type == 1) {  /* ClientHello */
                return APP_PROTO_TLS;
            }
        }
        return APP_PROTO_FAILED;
    }

    /* Validate version */
    if (version < TLS_VERSION_SSL30 || version > TLS_VERSION_TLS13) {
        return APP_PROTO_FAILED;
    }

    /* Validate record length (max 16KB for TLS) */
    if (record_len > 16384) {
        return APP_PROTO_FAILED;
    }

    /* For handshake records, validate handshake type */
    if (content_type == TLS_RECORD_HANDSHAKE && len >= 6) {
        uint8_t handshake_type = data[5];

        /* Common handshake types */
        if (handshake_type == TLS_HANDSHAKE_CLIENT_HELLO ||
            handshake_type == TLS_HANDSHAKE_SERVER_HELLO ||
            handshake_type == TLS_HANDSHAKE_CERTIFICATE ||
            handshake_type == TLS_HANDSHAKE_SERVER_KEY_EXCHANGE ||
            handshake_type == TLS_HANDSHAKE_CERTIFICATE_REQUEST ||
            handshake_type == TLS_HANDSHAKE_SERVER_HELLO_DONE) {
            return APP_PROTO_TLS;
        }

        /* Unknown handshake type, but valid TLS record structure */
        /* handshake_type is uint8_t, so it's always valid 0-255 */
        return APP_PROTO_TLS;
    }

    /* Valid TLS record structure for other content types */
    if (content_type == TLS_RECORD_APPLICATION_DATA ||
        content_type == TLS_RECORD_CHANGE_CIPHER_SPEC ||
        content_type == TLS_RECORD_ALERT ||
        content_type == TLS_RECORD_HEARTBEAT) {
        return APP_PROTO_TLS;
    }

    return APP_PROTO_UNKNOWN;
}

int proto_detect_register_tls(void)
{
    /* Register probing parser for both directions on port 443 and any port */
    int ret = 0;

    /* Port 443 (HTTPS) */
    ret = proto_detect_register_prober(
        APP_PROTO_TLS,
        443,                        /* Port 443 */
        5,                          /* Minimum 5 bytes (TLS header) */
        64,                         /* Examine up to 64 bytes */
        PROTO_DETECT_DIR_BOTH,      /* Both directions */
        tls_probing_parser
    );

    /* Any port (TLS can be on non-standard ports) */
    ret |= proto_detect_register_prober(
        APP_PROTO_TLS,
        0,                          /* Any port */
        5,                          /* Minimum 5 bytes */
        64,                         /* Examine up to 64 bytes */
        PROTO_DETECT_DIR_BOTH,      /* Both directions */
        tls_probing_parser
    );

    if (ret == 0) {
        RTE_LOG(INFO, TLS, "Registered TLS detection probing parser\n");
    }

    return ret;
}
