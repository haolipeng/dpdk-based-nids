/*
 * NetDefender - HTTP Protocol Detection
 *
 * Detects HTTP/1.x traffic using pattern matching on HTTP methods and versions.
 */

#include "proto_detect.h"
#include "app_proto.h"
#include <rte_log.h>
#include <string.h>

#define RTE_LOGTYPE_HTTP RTE_LOGTYPE_USER2

/* HTTP request methods */
static const char *http_methods[] = {
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "HEAD ",
    "OPTIONS ",
    "TRACE ",
    "CONNECT ",
    "PATCH ",
    NULL
};

/* HTTP response versions */
static const char *http_versions[] = {
    "HTTP/1.0",
    "HTTP/1.1",
    "HTTP/2",
    NULL
};

int proto_detect_register_http(void)
{
    int registered = 0;

    /* Register request method patterns (client to server) */
    for (int i = 0; http_methods[i] != NULL; i++) {
        const char *method = http_methods[i];
        int ret = proto_detect_register_pattern(
            APP_PROTO_HTTP,
            method,
            strlen(method),
            8,      /* Search within first 8 bytes */
            0,      /* Start from offset 0 */
            PROTO_DETECT_DIR_TOSERVER,
            false   /* Case-insensitive */
        );

        if (ret == 0) {
            registered++;
        }
    }

    /* Register response version patterns (server to client) */
    for (int i = 0; http_versions[i] != NULL; i++) {
        const char *version = http_versions[i];
        int ret = proto_detect_register_pattern(
            APP_PROTO_HTTP,
            version,
            strlen(version),
            16,     /* Search within first 16 bytes */
            0,      /* Start from offset 0 */
            PROTO_DETECT_DIR_TOCLIENT,
            false   /* Case-insensitive */
        );

        if (ret == 0) {
            registered++;
        }
    }

    RTE_LOG(INFO, HTTP, "Registered %d HTTP detection patterns\n", registered);

    return 0;
}
