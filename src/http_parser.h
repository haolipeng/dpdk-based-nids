/*
 * NetDefender - HTTP Protocol Parser
 *
 * This module provides HTTP/1.x request and response parsing.
 * Extracts key fields like method, URI, headers, status code, etc.
 */

#ifndef __HTTP_PARSER_H__
#define __HTTP_PARSER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations */
struct flow;

/* HTTP method enumeration */
typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_MAX
} http_method_t;

/* HTTP version */
typedef enum {
    HTTP_VERSION_UNKNOWN = 0,
    HTTP_VERSION_09,        /* HTTP/0.9 */
    HTTP_VERSION_10,        /* HTTP/1.0 */
    HTTP_VERSION_11,        /* HTTP/1.1 */
    HTTP_VERSION_20,        /* HTTP/2.0 */
} http_version_t;

/* HTTP transaction state */
typedef enum {
    HTTP_STATE_IDLE = 0,
    HTTP_STATE_REQUEST_LINE,
    HTTP_STATE_REQUEST_HEADERS,
    HTTP_STATE_REQUEST_BODY,
    HTTP_STATE_RESPONSE_LINE,
    HTTP_STATE_RESPONSE_HEADERS,
    HTTP_STATE_RESPONSE_BODY,
    HTTP_STATE_DONE,
    HTTP_STATE_ERROR
} http_state_t;

/* HTTP header field */
typedef struct http_header {
    char *name;                 /* Header name (e.g., "Content-Type") */
    char *value;                /* Header value */
    uint16_t name_len;          /* Name length */
    uint16_t value_len;         /* Value length */
    struct http_header *next;   /* Next header in list */
} http_header_t;

/* HTTP request structure */
typedef struct http_request {
    http_method_t method;       /* HTTP method */
    char *uri;                  /* Request URI */
    uint16_t uri_len;           /* URI length */
    char *host;                 /* Host header value */
    uint16_t host_len;          /* Host length */
    http_version_t version;     /* HTTP version */

    http_header_t *headers;     /* Request headers */
    uint16_t header_count;      /* Number of headers */

    uint64_t content_length;    /* Content-Length header value */
    bool has_content_length;    /* Content-Length present */

    char *content_type;         /* Content-Type header value */
    uint16_t content_type_len;  /* Content-Type length */

    char *user_agent;           /* User-Agent header value */
    uint16_t user_agent_len;    /* User-Agent length */

    bool complete;              /* Request parsing complete */
} http_request_t;

/* HTTP response structure */
typedef struct http_response {
    http_version_t version;     /* HTTP version */
    uint16_t status_code;       /* Status code (200, 404, etc.) */
    char *reason_phrase;        /* Reason phrase ("OK", "Not Found") */
    uint16_t reason_phrase_len; /* Reason phrase length */

    http_header_t *headers;     /* Response headers */
    uint16_t header_count;      /* Number of headers */

    uint64_t content_length;    /* Content-Length header value */
    bool has_content_length;    /* Content-Length present */

    char *content_type;         /* Content-Type header value */
    uint16_t content_type_len;  /* Content-Type length */

    char *server;               /* Server header value */
    uint16_t server_len;        /* Server length */

    bool complete;              /* Response parsing complete */
} http_response_t;

/* HTTP transaction (request + response pair) */
typedef struct http_transaction {
    http_request_t *request;
    http_response_t *response;
    http_state_t state;

    uint64_t request_ts;        /* Request timestamp */
    uint64_t response_ts;       /* Response timestamp */

    struct http_transaction *next;  /* Next transaction in list */
} http_transaction_t;

/* HTTP connection state (per flow) */
typedef struct http_conn {
    http_transaction_t *transactions;   /* List of transactions */
    http_transaction_t *current_tx;     /* Current transaction */
    uint32_t tx_count;                  /* Total transaction count */

    /* Parser state */
    http_state_t state;
    char *parse_buffer;         /* Buffer for incomplete data */
    uint32_t parse_buffer_len;  /* Buffer length */
    uint32_t parse_buffer_size; /* Buffer allocated size */

    /* Statistics */
    uint64_t requests_parsed;
    uint64_t responses_parsed;
    uint64_t parse_errors;
} http_conn_t;

/**
 * @brief Initialize HTTP parser for a flow
 *
 * @param flow Flow to attach HTTP parser to
 * @return HTTP connection state, or NULL on error
 */
http_conn_t *http_parser_init(struct flow *flow);

/**
 * @brief Free HTTP parser state
 *
 * @param conn HTTP connection state to free
 */
void http_parser_free(http_conn_t *conn);

/**
 * @brief Parse HTTP data (request or response)
 *
 * This function should be called with reassembled stream data.
 * It automatically determines if data is a request or response.
 *
 * @param conn HTTP connection state
 * @param data Data to parse
 * @param len Data length
 * @param direction 0 = to server (request), 1 = to client (response)
 * @return Number of bytes consumed, or -1 on error
 */
int http_parser_parse(http_conn_t *conn, const uint8_t *data, uint32_t len,
                      uint8_t direction);

/**
 * @brief Get current HTTP transaction
 *
 * @param conn HTTP connection state
 * @return Current transaction, or NULL if none
 */
http_transaction_t *http_get_current_transaction(http_conn_t *conn);

/**
 * @brief Convert HTTP method to string
 *
 * @param method HTTP method enum
 * @return Method string (e.g., "GET")
 */
const char *http_method_to_string(http_method_t method);

/**
 * @brief Convert HTTP version to string
 *
 * @param version HTTP version enum
 * @return Version string (e.g., "HTTP/1.1")
 */
const char *http_version_to_string(http_version_t version);

/**
 * @brief Find header by name
 *
 * @param headers Header list
 * @param name Header name to find (case-insensitive)
 * @return Header value, or NULL if not found
 */
http_header_t *http_find_header(http_header_t *headers, const char *name);

/**
 * @brief Get statistics string
 *
 * @param conn HTTP connection state
 * @param buf Output buffer
 * @param buf_size Buffer size
 */
void http_get_stats(const http_conn_t *conn, char *buf, size_t buf_size);

#endif /* __HTTP_PARSER_H__ */
