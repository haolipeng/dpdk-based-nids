/*
 * NetDefender - HTTP Protocol Parser Implementation
 *
 * This module implements HTTP/1.x parsing for requests and responses.
 */

#include "http_parser.h"
#include "flow.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>

#define RTE_LOGTYPE_HTTP_PARSER RTE_LOGTYPE_USER5

/* Maximum sizes */
#define HTTP_MAX_HEADER_SIZE    (8 * 1024)      /* 8KB for headers */
#define HTTP_MAX_HEADERS        50              /* Max 50 headers */
#define HTTP_MAX_URI_LEN        2048            /* Max URI length */
#define HTTP_PARSE_BUFFER_SIZE  (16 * 1024)    /* 16KB parse buffer */

/* Helper macros */
#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_CRLF(ptr, len) ((len) >= 2 && (ptr)[0] == '\r' && (ptr)[1] == '\n')
#define IS_LF(ptr, len) ((len) >= 1 && (ptr)[0] == '\n')

/* Method name mapping */
static const char *http_method_names[] = {
    [HTTP_METHOD_UNKNOWN] = "UNKNOWN",
    [HTTP_METHOD_GET]     = "GET",
    [HTTP_METHOD_POST]    = "POST",
    [HTTP_METHOD_PUT]     = "PUT",
    [HTTP_METHOD_DELETE]  = "DELETE",
    [HTTP_METHOD_HEAD]    = "HEAD",
    [HTTP_METHOD_OPTIONS] = "OPTIONS",
    [HTTP_METHOD_TRACE]   = "TRACE",
    [HTTP_METHOD_CONNECT] = "CONNECT",
    [HTTP_METHOD_PATCH]   = "PATCH",
};

const char *http_method_to_string(http_method_t method)
{
    if (method >= HTTP_METHOD_MAX) {
        return "UNKNOWN";
    }
    return http_method_names[method];
}

const char *http_version_to_string(http_version_t version)
{
    switch (version) {
        case HTTP_VERSION_09: return "HTTP/0.9";
        case HTTP_VERSION_10: return "HTTP/1.0";
        case HTTP_VERSION_11: return "HTTP/1.1";
        case HTTP_VERSION_20: return "HTTP/2.0";
        default: return "HTTP/?.?";
    }
}

/**
 * @brief Parse HTTP method from string
 */
static http_method_t parse_method(const char *str, size_t len)
{
    if (len == 3 && strncasecmp(str, "GET", 3) == 0) {
        return HTTP_METHOD_GET;
    } else if (len == 4 && strncasecmp(str, "POST", 4) == 0) {
        return HTTP_METHOD_POST;
    } else if (len == 3 && strncasecmp(str, "PUT", 3) == 0) {
        return HTTP_METHOD_PUT;
    } else if (len == 6 && strncasecmp(str, "DELETE", 6) == 0) {
        return HTTP_METHOD_DELETE;
    } else if (len == 4 && strncasecmp(str, "HEAD", 4) == 0) {
        return HTTP_METHOD_HEAD;
    } else if (len == 7 && strncasecmp(str, "OPTIONS", 7) == 0) {
        return HTTP_METHOD_OPTIONS;
    } else if (len == 5 && strncasecmp(str, "TRACE", 5) == 0) {
        return HTTP_METHOD_TRACE;
    } else if (len == 7 && strncasecmp(str, "CONNECT", 7) == 0) {
        return HTTP_METHOD_CONNECT;
    } else if (len == 5 && strncasecmp(str, "PATCH", 5) == 0) {
        return HTTP_METHOD_PATCH;
    }
    return HTTP_METHOD_UNKNOWN;
}

/**
 * @brief Parse HTTP version from string
 */
static http_version_t parse_version(const char *str, size_t len)
{
    if (len >= 8) {
        if (strncmp(str, "HTTP/0.9", 8) == 0) return HTTP_VERSION_09;
        if (strncmp(str, "HTTP/1.0", 8) == 0) return HTTP_VERSION_10;
        if (strncmp(str, "HTTP/1.1", 8) == 0) return HTTP_VERSION_11;
        if (strncmp(str, "HTTP/2.0", 8) == 0) return HTTP_VERSION_20;
    }
    return HTTP_VERSION_UNKNOWN;
}

/**
 * @brief Find end of line (CRLF or LF)
 */
static const uint8_t *find_eol(const uint8_t *data, uint32_t len, uint32_t *eol_len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (IS_CRLF(data + i, len - i)) {
            *eol_len = 2;
            return data + i;
        } else if (IS_LF(data + i, len - i)) {
            *eol_len = 1;
            return data + i;
        }
    }
    return NULL;
}

/**
 * @brief Allocate and copy string
 */
static char *strndup_malloc(const char *str, size_t len)
{
    char *result = rte_malloc("http_string", len + 1, 0);
    if (result) {
        memcpy(result, str, len);
        result[len] = '\0';
    }
    return result;
}

/**
 * @brief Free HTTP header list
 */
static void free_headers(http_header_t *headers)
{
    while (headers) {
        http_header_t *next = headers->next;
        if (headers->name) rte_free(headers->name);
        if (headers->value) rte_free(headers->value);
        rte_free(headers);
        headers = next;
    }
}

/**
 * @brief Free HTTP request
 */
static void free_request(http_request_t *req)
{
    if (!req) return;
    if (req->uri) rte_free(req->uri);
    if (req->host) rte_free(req->host);
    if (req->content_type) rte_free(req->content_type);
    if (req->user_agent) rte_free(req->user_agent);
    free_headers(req->headers);
    rte_free(req);
}

/**
 * @brief Free HTTP response
 */
static void free_response(http_response_t *resp)
{
    if (!resp) return;
    if (resp->reason_phrase) rte_free(resp->reason_phrase);
    if (resp->content_type) rte_free(resp->content_type);
    if (resp->server) rte_free(resp->server);
    free_headers(resp->headers);
    rte_free(resp);
}

/**
 * @brief Parse HTTP request line
 * Format: METHOD URI HTTP/VERSION\r\n
 */
static int parse_request_line(http_conn_t *conn, const uint8_t *data, uint32_t len,
                               http_request_t *req)
{
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *method_start, *method_end;
    const uint8_t *uri_start, *uri_end;
    const uint8_t *version_start, *version_end;

    /* Find end of line */
    uint32_t eol_len;
    const uint8_t *eol = find_eol(data, len, &eol_len);
    if (!eol) {
        return 0;  /* Need more data */
    }

    end = eol;

    /* Parse method */
    method_start = ptr;
    while (ptr < end && !IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) return -1;  /* Invalid */
    method_end = ptr;

    req->method = parse_method((const char *)method_start, method_end - method_start);
    if (req->method == HTTP_METHOD_UNKNOWN) {
        RTE_LOG(WARNING, HTTP_PARSER, "Unknown HTTP method\n");
    }

    /* Skip spaces */
    while (ptr < end && IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) return -1;

    /* Parse URI */
    uri_start = ptr;
    while (ptr < end && !IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) return -1;
    uri_end = ptr;

    size_t uri_len = uri_end - uri_start;
    if (uri_len > HTTP_MAX_URI_LEN) uri_len = HTTP_MAX_URI_LEN;
    req->uri = strndup_malloc((const char *)uri_start, uri_len);
    req->uri_len = uri_len;

    /* Skip spaces */
    while (ptr < end && IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) {
        /* HTTP/0.9 doesn't have version */
        req->version = HTTP_VERSION_09;
        return (eol - data) + eol_len;
    }

    /* Parse version */
    version_start = ptr;
    while (ptr < end && !IS_SPACE(*ptr)) ptr++;
    version_end = ptr;

    req->version = parse_version((const char *)version_start, version_end - version_start);

    return (eol - data) + eol_len;
}

/**
 * @brief Parse HTTP response status line
 * Format: HTTP/VERSION STATUS REASON\r\n
 */
static int parse_response_line(http_conn_t *conn, const uint8_t *data, uint32_t len,
                                http_response_t *resp)
{
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *version_start, *version_end;
    const uint8_t *status_start, *status_end;
    const uint8_t *reason_start, *reason_end;

    /* Find end of line */
    uint32_t eol_len;
    const uint8_t *eol = find_eol(data, len, &eol_len);
    if (!eol) {
        return 0;  /* Need more data */
    }

    end = eol;

    /* Parse version */
    version_start = ptr;
    while (ptr < end && !IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) return -1;
    version_end = ptr;

    resp->version = parse_version((const char *)version_start, version_end - version_start);

    /* Skip spaces */
    while (ptr < end && IS_SPACE(*ptr)) ptr++;
    if (ptr >= end) return -1;

    /* Parse status code */
    status_start = ptr;
    while (ptr < end && isdigit(*ptr)) ptr++;
    if (ptr >= end || ptr == status_start) return -1;
    status_end = ptr;

    /* Convert status code to integer */
    char status_buf[4] = {0};
    size_t status_len = status_end - status_start;
    if (status_len > 3) status_len = 3;
    memcpy(status_buf, status_start, status_len);
    resp->status_code = atoi(status_buf);

    /* Skip spaces */
    while (ptr < end && IS_SPACE(*ptr)) ptr++;

    /* Parse reason phrase (optional) */
    if (ptr < end) {
        reason_start = ptr;
        reason_end = end;
        size_t reason_len = reason_end - reason_start;
        resp->reason_phrase = strndup_malloc((const char *)reason_start, reason_len);
        resp->reason_phrase_len = reason_len;
    }

    return (eol - data) + eol_len;
}

/**
 * @brief Parse HTTP header line
 * Format: Name: Value\r\n
 */
static int parse_header(http_conn_t *conn, const uint8_t *data, uint32_t len,
                        http_header_t **header_out)
{
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *name_start, *name_end;
    const uint8_t *value_start, *value_end;

    /* Find end of line */
    uint32_t eol_len;
    const uint8_t *eol = find_eol(data, len, &eol_len);
    if (!eol) {
        return 0;  /* Need more data */
    }

    /* Check for empty line (end of headers) */
    if (eol == data) {
        return eol_len;  /* End of headers */
    }

    end = eol;

    /* Parse header name */
    name_start = ptr;
    while (ptr < end && *ptr != ':') ptr++;
    if (ptr >= end) return -1;  /* Invalid */
    name_end = ptr;

    /* Skip ':' */
    ptr++;

    /* Skip leading spaces in value */
    while (ptr < end && IS_SPACE(*ptr)) ptr++;

    /* Parse header value */
    value_start = ptr;
    value_end = end;

    /* Trim trailing spaces */
    while (value_end > value_start && IS_SPACE(*(value_end - 1))) {
        value_end--;
    }

    /* Allocate header */
    http_header_t *header = rte_zmalloc("http_header", sizeof(http_header_t), 0);
    if (!header) {
        return -1;
    }

    header->name = strndup_malloc((const char *)name_start, name_end - name_start);
    header->name_len = name_end - name_start;
    header->value = strndup_malloc((const char *)value_start, value_end - value_start);
    header->value_len = value_end - value_start;

    *header_out = header;

    return (eol - data) + eol_len;
}

http_header_t *http_find_header(http_header_t *headers, const char *name)
{
    for (http_header_t *h = headers; h != NULL; h = h->next) {
        if (h->name && strcasecmp(h->name, name) == 0) {
            return h;
        }
    }
    return NULL;
}

/**
 * @brief Extract common headers from request
 */
static void extract_request_headers(http_request_t *req)
{
    http_header_t *h;

    /* Host */
    h = http_find_header(req->headers, "Host");
    if (h) {
        req->host = strndup_malloc(h->value, h->value_len);
        req->host_len = h->value_len;
    }

    /* Content-Length */
    h = http_find_header(req->headers, "Content-Length");
    if (h) {
        req->content_length = strtoull(h->value, NULL, 10);
        req->has_content_length = true;
    }

    /* Content-Type */
    h = http_find_header(req->headers, "Content-Type");
    if (h) {
        req->content_type = strndup_malloc(h->value, h->value_len);
        req->content_type_len = h->value_len;
    }

    /* User-Agent */
    h = http_find_header(req->headers, "User-Agent");
    if (h) {
        req->user_agent = strndup_malloc(h->value, h->value_len);
        req->user_agent_len = h->value_len;
    }
}

/**
 * @brief Extract common headers from response
 */
static void extract_response_headers(http_response_t *resp)
{
    http_header_t *h;

    /* Content-Length */
    h = http_find_header(resp->headers, "Content-Length");
    if (h) {
        resp->content_length = strtoull(h->value, NULL, 10);
        resp->has_content_length = true;
    }

    /* Content-Type */
    h = http_find_header(resp->headers, "Content-Type");
    if (h) {
        resp->content_type = strndup_malloc(h->value, h->value_len);
        resp->content_type_len = h->value_len;
    }

    /* Server */
    h = http_find_header(resp->headers, "Server");
    if (h) {
        resp->server = strndup_malloc(h->value, h->value_len);
        resp->server_len = h->value_len;
    }
}

/**
 * @brief Parse HTTP request headers
 */
static int parse_request_headers(http_conn_t *conn, const uint8_t *data, uint32_t len,
                                 http_request_t *req)
{
    uint32_t consumed = 0;
    http_header_t **header_tail = &req->headers;

    while (consumed < len) {
        http_header_t *header = NULL;
        int ret = parse_header(conn, data + consumed, len - consumed, &header);

        if (ret < 0) {
            return -1;  /* Parse error */
        } else if (ret == 0) {
            return consumed;  /* Need more data */
        } else if (header == NULL) {
            /* Empty line - end of headers */
            consumed += ret;
            req->complete = true;
            extract_request_headers(req);
            return consumed;
        } else {
            /* Add header to list */
            *header_tail = header;
            header_tail = &header->next;
            req->header_count++;
            consumed += ret;

            if (req->header_count >= HTTP_MAX_HEADERS) {
                RTE_LOG(WARNING, HTTP_PARSER, "Too many headers\n");
                req->complete = true;
                extract_request_headers(req);
                return consumed;
            }
        }
    }

    return consumed;
}

/**
 * @brief Parse HTTP response headers
 */
static int parse_response_headers(http_conn_t *conn, const uint8_t *data, uint32_t len,
                                  http_response_t *resp)
{
    uint32_t consumed = 0;
    http_header_t **header_tail = &resp->headers;

    while (consumed < len) {
        http_header_t *header = NULL;
        int ret = parse_header(conn, data + consumed, len - consumed, &header);

        if (ret < 0) {
            return -1;  /* Parse error */
        } else if (ret == 0) {
            return consumed;  /* Need more data */
        } else if (header == NULL) {
            /* Empty line - end of headers */
            consumed += ret;
            resp->complete = true;
            extract_response_headers(resp);
            return consumed;
        } else {
            /* Add header to list */
            *header_tail = header;
            header_tail = &header->next;
            resp->header_count++;
            consumed += ret;

            if (resp->header_count >= HTTP_MAX_HEADERS) {
                RTE_LOG(WARNING, HTTP_PARSER, "Too many headers\n");
                resp->complete = true;
                extract_response_headers(resp);
                return consumed;
            }
        }
    }

    return consumed;
}

http_conn_t *http_parser_init(struct flow *flow)
{
    http_conn_t *conn = rte_zmalloc("http_conn", sizeof(http_conn_t), 0);
    if (!conn) {
        return NULL;
    }

    conn->state = HTTP_STATE_IDLE;
    conn->parse_buffer_size = HTTP_PARSE_BUFFER_SIZE;
    conn->parse_buffer = rte_malloc("http_parse_buffer", conn->parse_buffer_size, 0);
    if (!conn->parse_buffer) {
        rte_free(conn);
        return NULL;
    }

    return conn;
}

void http_parser_free(http_conn_t *conn)
{
    if (!conn) return;

    /* Free transactions */
    http_transaction_t *tx = conn->transactions;
    while (tx) {
        http_transaction_t *next = tx->next;
        free_request(tx->request);
        free_response(tx->response);
        rte_free(tx);
        tx = next;
    }

    if (conn->parse_buffer) {
        rte_free(conn->parse_buffer);
    }

    rte_free(conn);
}

int http_parser_parse(http_conn_t *conn, const uint8_t *data, uint32_t len,
                      uint8_t direction)
{
    if (!conn || !data || len == 0) {
        return -1;
    }

    uint32_t consumed = 0;

    /* Determine if this is request or response */
    bool is_request = (direction == 0);  /* 0 = to server */

    if (is_request) {
        /* Parse request */
        if (conn->state == HTTP_STATE_IDLE || conn->state == HTTP_STATE_REQUEST_LINE) {
            /* Create new transaction */
            if (!conn->current_tx) {
                http_transaction_t *tx = rte_zmalloc("http_tx", sizeof(http_transaction_t), 0);
                if (!tx) return -1;

                tx->request = rte_zmalloc("http_request", sizeof(http_request_t), 0);
                if (!tx->request) {
                    rte_free(tx);
                    return -1;
                }

                tx->state = HTTP_STATE_REQUEST_LINE;
                conn->current_tx = tx;

                /* Add to transaction list */
                tx->next = conn->transactions;
                conn->transactions = tx;
                conn->tx_count++;
            }

            http_request_t *req = conn->current_tx->request;

            /* Parse request line */
            int ret = parse_request_line(conn, data, len, req);
            if (ret < 0) {
                conn->parse_errors++;
                conn->state = HTTP_STATE_ERROR;
                return -1;
            } else if (ret == 0) {
                return 0;  /* Need more data */
            }

            consumed += ret;
            conn->state = HTTP_STATE_REQUEST_HEADERS;
            conn->current_tx->state = HTTP_STATE_REQUEST_HEADERS;
        }

        if (conn->state == HTTP_STATE_REQUEST_HEADERS && consumed < len) {
            http_request_t *req = conn->current_tx->request;

            /* Parse headers */
            int ret = parse_request_headers(conn, data + consumed, len - consumed, req);
            if (ret < 0) {
                conn->parse_errors++;
                conn->state = HTTP_STATE_ERROR;
                return -1;
            }

            consumed += ret;

            if (req->complete) {
                conn->requests_parsed++;
                conn->state = HTTP_STATE_RESPONSE_LINE;  /* Wait for response */

                RTE_LOG(INFO, HTTP_PARSER,
                        "HTTP Request: %s %s HTTP/%s | Host: %s\n",
                        http_method_to_string(req->method),
                        req->uri ? req->uri : "<null>",
                        http_version_to_string(req->version),
                        req->host ? req->host : "-");
            }
        }
    } else {
        /* Parse response */
        if (conn->state == HTTP_STATE_RESPONSE_LINE) {
            if (!conn->current_tx) {
                RTE_LOG(WARNING, HTTP_PARSER, "Response without request\n");
                return -1;
            }

            if (!conn->current_tx->response) {
                conn->current_tx->response = rte_zmalloc("http_response",
                                                          sizeof(http_response_t), 0);
                if (!conn->current_tx->response) {
                    return -1;
                }
            }

            http_response_t *resp = conn->current_tx->response;

            /* Parse status line */
            int ret = parse_response_line(conn, data, len, resp);
            if (ret < 0) {
                conn->parse_errors++;
                conn->state = HTTP_STATE_ERROR;
                return -1;
            } else if (ret == 0) {
                return 0;  /* Need more data */
            }

            consumed += ret;
            conn->state = HTTP_STATE_RESPONSE_HEADERS;
            conn->current_tx->state = HTTP_STATE_RESPONSE_HEADERS;
        }

        if (conn->state == HTTP_STATE_RESPONSE_HEADERS && consumed < len) {
            http_response_t *resp = conn->current_tx->response;

            /* Parse headers */
            int ret = parse_response_headers(conn, data + consumed, len - consumed, resp);
            if (ret < 0) {
                conn->parse_errors++;
                conn->state = HTTP_STATE_ERROR;
                return -1;
            }

            consumed += ret;

            if (resp->complete) {
                conn->responses_parsed++;
                conn->state = HTTP_STATE_DONE;
                conn->current_tx->state = HTTP_STATE_DONE;

                RTE_LOG(INFO, HTTP_PARSER,
                        "HTTP Response: HTTP/%s %d %s | Content-Type: %s | Content-Length: %lu\n",
                        http_version_to_string(resp->version),
                        resp->status_code,
                        resp->reason_phrase ? resp->reason_phrase : "-",
                        resp->content_type ? resp->content_type : "-",
                        resp->content_length);

                /* Transaction complete, ready for next request */
                conn->current_tx = NULL;
                conn->state = HTTP_STATE_IDLE;
            }
        }
    }

    return consumed;
}

http_transaction_t *http_get_current_transaction(http_conn_t *conn)
{
    return conn ? conn->current_tx : NULL;
}

void http_get_stats(const http_conn_t *conn, char *buf, size_t buf_size)
{
    if (!conn || !buf || buf_size == 0) {
        return;
    }

    snprintf(buf, buf_size,
             "HTTP Stats: tx=%u req=%lu resp=%lu errors=%lu state=%d",
             conn->tx_count,
             conn->requests_parsed,
             conn->responses_parsed,
             conn->parse_errors,
             conn->state);
}
