/*
 * NetDefender - Application Layer Protocol Implementation
 *
 * This module implements protocol name mapping and utility functions.
 */

#include "app_proto.h"
#include <string.h>
#include <strings.h>  /* for strcasecmp */

/**
 * Protocol name mapping table
 * Must match the order of app_proto_t enum
 */
static const char *proto_names[] = {
    [APP_PROTO_UNKNOWN]   = "unknown",
    [APP_PROTO_HTTP]      = "http",
    [APP_PROTO_TLS]       = "tls",
    [APP_PROTO_DNS]       = "dns",
    [APP_PROTO_SMTP]      = "smtp",
    [APP_PROTO_IMAP]      = "imap",
    [APP_PROTO_POP3]      = "pop3",
    [APP_PROTO_FTP]       = "ftp",
    [APP_PROTO_FTP_DATA]  = "ftp-data",
    [APP_PROTO_SSH]       = "ssh",
    [APP_PROTO_TELNET]    = "telnet",
    [APP_PROTO_MYSQL]     = "mysql",
    [APP_PROTO_PGSQL]     = "pgsql",
    [APP_PROTO_REDIS]     = "redis",
    [APP_PROTO_MQTT]      = "mqtt",
    [APP_PROTO_AMQP]      = "amqp",
    [APP_PROTO_SMB]       = "smb",
    [APP_PROTO_NFS]       = "nfs",
    [APP_PROTO_DHCP]      = "dhcp",
    [APP_PROTO_FAILED]    = "failed",
};

/**
 * Protocol default port mapping table
 */
static const uint16_t proto_ports[] = {
    [APP_PROTO_UNKNOWN]   = 0,
    [APP_PROTO_HTTP]      = 80,
    [APP_PROTO_TLS]       = 443,
    [APP_PROTO_DNS]       = 53,
    [APP_PROTO_SMTP]      = 25,
    [APP_PROTO_IMAP]      = 143,
    [APP_PROTO_POP3]      = 110,
    [APP_PROTO_FTP]       = 21,
    [APP_PROTO_FTP_DATA]  = 20,
    [APP_PROTO_SSH]       = 22,
    [APP_PROTO_TELNET]    = 23,
    [APP_PROTO_MYSQL]     = 3306,
    [APP_PROTO_PGSQL]     = 5432,
    [APP_PROTO_REDIS]     = 6379,
    [APP_PROTO_MQTT]      = 1883,
    [APP_PROTO_AMQP]      = 5672,
    [APP_PROTO_SMB]       = 445,
    [APP_PROTO_NFS]       = 2049,
    [APP_PROTO_DHCP]      = 67,
    [APP_PROTO_FAILED]    = 0,
};

const char *app_proto_to_string(app_proto_t proto)
{
    if (proto >= APP_PROTO_MAX) {
        return "invalid";
    }

    const char *name = proto_names[proto];
    return name ? name : "unknown";
}

app_proto_t app_proto_from_string(const char *name)
{
    if (!name) {
        return APP_PROTO_UNKNOWN;
    }

    /* Linear search - OK for small number of protocols */
    for (int i = 0; i < APP_PROTO_MAX; i++) {
        if (proto_names[i] && strcasecmp(name, proto_names[i]) == 0) {
            return (app_proto_t)i;
        }
    }

    /* Check common aliases */
    if (strcasecmp(name, "https") == 0) {
        return APP_PROTO_TLS;
    }
    if (strcasecmp(name, "ssl") == 0) {
        return APP_PROTO_TLS;
    }
    if (strcasecmp(name, "postgresql") == 0) {
        return APP_PROTO_PGSQL;
    }

    return APP_PROTO_UNKNOWN;
}

uint16_t app_proto_default_port(app_proto_t proto)
{
    if (proto >= APP_PROTO_MAX) {
        return 0;
    }

    return proto_ports[proto];
}
