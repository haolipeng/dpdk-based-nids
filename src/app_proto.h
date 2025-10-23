/*
 * NetDefender - Application Layer Protocol Definitions
 *
 * This module defines application layer protocol enumerations and types
 * used throughout the protocol detection and parsing system.
 */

#ifndef __APP_PROTO_H__
#define __APP_PROTO_H__

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Application layer protocol enumeration
 *
 * This enum defines all supported application protocols.
 * Each protocol has a unique identifier used in flow tracking
 * and protocol detection.
 */
typedef enum {
    APP_PROTO_UNKNOWN = 0,      /* Unknown/not yet detected */

    /* Web protocols */
    APP_PROTO_HTTP,             /* HTTP/1.x */
    APP_PROTO_TLS,              /* TLS/SSL (HTTPS) */

    /* DNS */
    APP_PROTO_DNS,              /* DNS queries and responses */

    /* Email protocols */
    APP_PROTO_SMTP,             /* Simple Mail Transfer Protocol */
    APP_PROTO_IMAP,             /* Internet Message Access Protocol */
    APP_PROTO_POP3,             /* Post Office Protocol v3 */

    /* File transfer */
    APP_PROTO_FTP,              /* File Transfer Protocol */
    APP_PROTO_FTP_DATA,         /* FTP data channel */

    /* Remote access */
    APP_PROTO_SSH,              /* Secure Shell */
    APP_PROTO_TELNET,           /* Telnet */

    /* Database protocols */
    APP_PROTO_MYSQL,            /* MySQL database */
    APP_PROTO_PGSQL,            /* PostgreSQL database */
    APP_PROTO_REDIS,            /* Redis key-value store */

    /* Message queues */
    APP_PROTO_MQTT,             /* MQTT IoT protocol */
    APP_PROTO_AMQP,             /* Advanced Message Queuing Protocol */

    /* Network protocols */
    APP_PROTO_SMB,              /* Server Message Block (Windows shares) */
    APP_PROTO_NFS,              /* Network File System */
    APP_PROTO_DHCP,             /* Dynamic Host Configuration Protocol */

    /* Detection failed (definitely not a recognized protocol) */
    APP_PROTO_FAILED,           /* Detection attempted but failed */

    /* Must be last */
    APP_PROTO_MAX               /* Total number of protocols + 1 */
} app_proto_t;

/**
 * @brief Protocol detection confidence level
 *
 * Indicates how confident we are in the protocol detection result.
 */
typedef enum {
    PROTO_CONFIDENCE_LOW = 0,       /* Weak indicators only */
    PROTO_CONFIDENCE_MEDIUM,        /* Port + some content match */
    PROTO_CONFIDENCE_HIGH,          /* Strong content match */
    PROTO_CONFIDENCE_CERTAIN,       /* Complete protocol validation */
} proto_confidence_t;

/**
 * @brief Protocol detection result
 *
 * Contains the detected protocol and confidence level.
 */
typedef struct proto_detect_result {
    app_proto_t protocol;           /* Detected protocol */
    proto_confidence_t confidence;  /* Confidence level */
    bool reverse_flow;              /* True if detection was on reverse direction */
} proto_detect_result_t;

/**
 * @brief Convert protocol enum to string name
 *
 * @param proto Protocol enum value
 * @return String name of the protocol (e.g., "HTTP", "TLS")
 */
const char *app_proto_to_string(app_proto_t proto);

/**
 * @brief Convert string name to protocol enum
 *
 * @param name Protocol name string (case-insensitive)
 * @return Protocol enum value, or APP_PROTO_UNKNOWN if not found
 */
app_proto_t app_proto_from_string(const char *name);

/**
 * @brief Check if protocol is known/detected
 *
 * @param proto Protocol enum value
 * @return true if protocol is known (not UNKNOWN or FAILED)
 */
static inline bool app_proto_is_detected(app_proto_t proto)
{
    return (proto > APP_PROTO_UNKNOWN && proto < APP_PROTO_FAILED);
}

/**
 * @brief Check if protocol requires TLS/encryption
 *
 * @param proto Protocol enum value
 * @return true if protocol is encrypted (TLS, SSH, etc.)
 */
static inline bool app_proto_is_encrypted(app_proto_t proto)
{
    switch (proto) {
        case APP_PROTO_TLS:
        case APP_PROTO_SSH:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Get default port for a protocol
 *
 * @param proto Protocol enum value
 * @return Default port number, or 0 if no standard port
 */
uint16_t app_proto_default_port(app_proto_t proto);

#endif /* __APP_PROTO_H__ */
