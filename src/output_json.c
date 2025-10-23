/*
 * NetDefender - JSON Output Module Implementation
 *
 * Implements EVE JSON format output compatible with Suricata.
 */

#define _GNU_SOURCE

#include "output_json.h"
#include "flow.h"
#include "rule_engine.h"
#include "http_parser.h"
#include "dns_parser.h"
#include "tls_parser.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_JSON RTE_LOGTYPE_USER1

/* Default buffer size for JSON building */
#define JSON_BUFFER_SIZE  (16 * 1024)  /* 16KB */

/* ============================================================================
 * JSON Builder Implementation
 * ============================================================================ */

json_builder_t *json_builder_create(size_t initial_size)
{
    json_builder_t *jb = rte_zmalloc("json_builder", sizeof(json_builder_t), 0);
    if (!jb) return NULL;

    jb->size = initial_size > 0 ? initial_size : JSON_BUFFER_SIZE;
    jb->buf = rte_malloc("json_buf", jb->size, 0);
    if (!jb->buf) {
        rte_free(jb);
        return NULL;
    }

    jb->offset = 0;
    jb->indent_level = 0;
    jb->buf[0] = '\0';
    return jb;
}

void json_builder_free(json_builder_t *jb)
{
    if (!jb) return;
    if (jb->buf) rte_free(jb->buf);
    rte_free(jb);
}

static void json_builder_append(json_builder_t *jb, const char *str)
{
    size_t len = strlen(str);

    /* Ensure buffer is large enough */
    while (jb->offset + len + 1 >= jb->size) {
        size_t new_size = jb->size * 2;
        char *new_buf = rte_realloc(jb->buf, new_size, 0);
        if (!new_buf) {
            RTE_LOG(ERR, JSON, "Failed to resize JSON buffer\n");
            return;
        }
        jb->buf = new_buf;
        jb->size = new_size;
    }

    memcpy(jb->buf + jb->offset, str, len);
    jb->offset += len;
    jb->buf[jb->offset] = '\0';
}

static void json_builder_append_char(json_builder_t *jb, char c)
{
    char buf[2] = {c, '\0'};
    json_builder_append(jb, buf);
}

static bool json_needs_comma(json_builder_t *jb)
{
    /* Check if last non-whitespace character is { or [ */
    for (int i = jb->offset - 1; i >= 0; i--) {
        char c = jb->buf[i];
        if (c == '{' || c == '[') return false;
        if (c == ',' || c == ':') return false;
        if (c != ' ' && c != '\n' && c != '\t') return true;
    }
    return false;
}

void json_builder_start_object(json_builder_t *jb)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");
    json_builder_append_char(jb, '{');
    jb->indent_level++;
}

void json_builder_end_object(json_builder_t *jb)
{
    jb->indent_level--;
    json_builder_append_char(jb, '}');
}

void json_builder_start_array(json_builder_t *jb)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");
    json_builder_append_char(jb, '[');
    jb->indent_level++;
}

void json_builder_end_array(json_builder_t *jb)
{
    jb->indent_level--;
    json_builder_append_char(jb, ']');
}

static void json_escape_string(const char *input, char *output, size_t output_size)
{
    size_t out_idx = 0;

    for (size_t i = 0; input[i] && out_idx < output_size - 2; i++) {
        char c = input[i];
        if (c == '"' || c == '\\') {
            output[out_idx++] = '\\';
            output[out_idx++] = c;
        } else if (c == '\n') {
            output[out_idx++] = '\\';
            output[out_idx++] = 'n';
        } else if (c == '\r') {
            output[out_idx++] = '\\';
            output[out_idx++] = 'r';
        } else if (c == '\t') {
            output[out_idx++] = '\\';
            output[out_idx++] = 't';
        } else if ((unsigned char)c < 32) {
            /* Skip control characters */
            output[out_idx++] = '?';
        } else {
            output[out_idx++] = c;
        }
    }
    output[out_idx] = '\0';
}

void json_builder_add_string(json_builder_t *jb, const char *key, const char *value)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");

    char buf[4096];
    char escaped[4096];

    json_escape_string(value ? value : "", escaped, sizeof(escaped));
    snprintf(buf, sizeof(buf), "\"%s\":\"%s\"", key, escaped);
    json_builder_append(jb, buf);
}

void json_builder_add_int(json_builder_t *jb, const char *key, int64_t value)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");

    char buf[256];
    snprintf(buf, sizeof(buf), "\"%s\":%ld", key, value);
    json_builder_append(jb, buf);
}

void json_builder_add_uint(json_builder_t *jb, const char *key, uint64_t value)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");

    char buf[256];
    snprintf(buf, sizeof(buf), "\"%s\":%lu", key, value);
    json_builder_append(jb, buf);
}

void json_builder_add_bool(json_builder_t *jb, const char *key, bool value)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");

    char buf[256];
    snprintf(buf, sizeof(buf), "\"%s\":%s", key, value ? "true" : "false");
    json_builder_append(jb, buf);
}

void json_builder_add_null(json_builder_t *jb, const char *key)
{
    if (json_needs_comma(jb)) json_builder_append(jb, ",");

    char buf[256];
    snprintf(buf, sizeof(buf), "\"%s\":null", key);
    json_builder_append(jb, buf);
}

const char *json_builder_get_string(json_builder_t *jb)
{
    return jb ? jb->buf : NULL;
}

void json_builder_reset(json_builder_t *jb)
{
    if (!jb) return;
    jb->offset = 0;
    jb->indent_level = 0;
    jb->buf[0] = '\0';
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

void json_add_timestamp(json_builder_t *jb, const char *key, const struct timeval *timestamp)
{
    struct timeval tv;
    if (!timestamp) {
        gettimeofday(&tv, NULL);
        timestamp = &tv;
    }

    char buf[64];
    struct tm tm;
    gmtime_r(&timestamp->tv_sec, &tm);
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, timestamp->tv_usec);

    json_builder_add_string(jb, key, buf);
}

void json_add_flow_info(json_builder_t *jb, struct flow *flow)
{
    if (!flow) return;

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    if (flow->flags & FLOW_IPV4) {
        inet_ntop(AF_INET, &flow->src_addr.addr_data32[0], src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &flow->dst_addr.addr_data32[0], dst_ip, sizeof(dst_ip));
    } else {
        inet_ntop(AF_INET6, flow->src_addr.addr_data32, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, flow->dst_addr.addr_data32, dst_ip, sizeof(dst_ip));
    }

    json_builder_add_string(jb, "src_ip", src_ip);
    json_builder_add_uint(jb, "src_port", flow->src_port);
    json_builder_add_string(jb, "dest_ip", dst_ip);
    json_builder_add_uint(jb, "dest_port", flow->dst_port);
    json_builder_add_string(jb, "proto", flow->proto == IPPROTO_TCP ? "TCP" :
                                          flow->proto == IPPROTO_UDP ? "UDP" : "OTHER");
}

/* ============================================================================
 * JSON Output Context
 * ============================================================================ */

json_output_ctx_t *json_output_init(const char *filename, bool indent)
{
    json_output_ctx_t *ctx = rte_zmalloc("json_output_ctx",
                                          sizeof(json_output_ctx_t), 0);
    if (!ctx) return NULL;

    if (filename) {
        ctx->filename = strdup(filename);
        ctx->fp = fopen(filename, "a");
        if (!ctx->fp) {
            RTE_LOG(ERR, JSON, "Failed to open output file: %s\n", filename);
            free(ctx->filename);
            rte_free(ctx);
            return NULL;
        }
    } else {
        ctx->fp = stdout;
        ctx->filename = NULL;
    }

    ctx->indent = indent;
    ctx->log_flow_info = true;
    ctx->log_timestamp = true;
    gettimeofday((struct timeval *)&ctx->last_rotate, NULL);

    RTE_LOG(INFO, JSON, "JSON output initialized: %s\n",
            filename ? filename : "stdout");

    return ctx;
}

void json_output_free(json_output_ctx_t *ctx)
{
    if (!ctx) return;

    if (ctx->fp && ctx->fp != stdout) {
        fclose(ctx->fp);
    }
    if (ctx->filename) {
        free(ctx->filename);
    }
    rte_free(ctx);
}

void json_output_enable_rotation(json_output_ctx_t *ctx, uint64_t max_size,
                                   uint64_t interval, uint32_t count)
{
    if (!ctx) return;
    ctx->rotate_enabled = true;
    ctx->rotate_size = max_size;
    ctx->rotate_interval = interval;
    ctx->rotate_count = count;
}

int json_output_rotate(json_output_ctx_t *ctx)
{
    if (!ctx || !ctx->filename || !ctx->rotate_enabled) return 0;

    struct timeval now;
    gettimeofday(&now, NULL);

    /* Check if rotation is needed */
    bool should_rotate = false;
    if (ctx->rotate_size > 0 && ctx->current_size >= ctx->rotate_size) {
        should_rotate = true;
    }
    if (ctx->rotate_interval > 0 &&
        (uint64_t)(now.tv_sec - ctx->last_rotate) >= ctx->rotate_interval) {
        should_rotate = true;
    }

    if (!should_rotate) return 0;

    /* Close current file */
    if (ctx->fp) fclose(ctx->fp);

    /* Rotate files */
    for (uint32_t i = ctx->rotate_count - 1; i > 0; i--) {
        char old_name[512], new_name[512];
        snprintf(old_name, sizeof(old_name), "%s.%u", ctx->filename, i - 1);
        snprintf(new_name, sizeof(new_name), "%s.%u", ctx->filename, i);
        rename(old_name, new_name);
    }

    /* Rename current to .0 */
    char rotated_name[512];
    snprintf(rotated_name, sizeof(rotated_name), "%s.0", ctx->filename);
    rename(ctx->filename, rotated_name);

    /* Open new file */
    ctx->fp = fopen(ctx->filename, "a");
    if (!ctx->fp) {
        RTE_LOG(ERR, JSON, "Failed to open rotated file: %s\n", ctx->filename);
        return -1;
    }

    ctx->current_size = 0;
    ctx->last_rotate = now.tv_sec;
    ctx->rotations++;

    RTE_LOG(INFO, JSON, "Log file rotated: %s\n", ctx->filename);
    return 0;
}

static int json_output_write(json_output_ctx_t *ctx, const char *json_str)
{
    if (!ctx || !ctx->fp || !json_str) return -1;

    size_t len = strlen(json_str);
    if (fprintf(ctx->fp, "%s\n", json_str) < 0) {
        ctx->write_errors++;
        return -1;
    }
    fflush(ctx->fp);

    ctx->events_written++;
    ctx->bytes_written += len + 1;
    ctx->current_size += len + 1;

    /* Check if rotation is needed */
    json_output_rotate(ctx);

    return 0;
}

/* ============================================================================
 * Alert Output
 * ============================================================================ */

int json_output_alert(json_output_ctx_t *ctx, struct alert *alert,
                      struct flow *flow)
{
    if (!ctx || !alert) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", &alert->timestamp);
    }

    json_builder_add_string(jb, "event_type", "alert");

    /* Flow info */
    if (ctx->log_flow_info && flow) {
        json_add_flow_info(jb, flow);
    }

    /* Alert object */
    json_builder_add_string(jb, "alert", NULL);
    json_builder_start_object(jb);
    json_builder_add_string(jb, "action", "allowed");
    json_builder_add_uint(jb, "gid", 1);
    json_builder_add_uint(jb, "signature_id", alert->rule_id);
    json_builder_add_uint(jb, "rev", 1);
    json_builder_add_string(jb, "signature", alert->message ? alert->message : "");
    json_builder_add_string(jb, "category", alert_category_to_string(alert->category));
    json_builder_add_string(jb, "severity", alert_severity_to_string(alert->severity));
    json_builder_end_object(jb);

    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

/* ============================================================================
 * HTTP Output
 * ============================================================================ */

int json_output_http(json_output_ctx_t *ctx, struct http_transaction *tx,
                     struct flow *flow)
{
    if (!ctx || !tx) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", NULL);
    }

    json_builder_add_string(jb, "event_type", "http");

    if (ctx->log_flow_info && flow) {
        json_add_flow_info(jb, flow);
    }

    /* HTTP object */
    json_builder_add_string(jb, "http", NULL);
    json_builder_start_object(jb);

    if (tx->request) {
        http_request_t *req = tx->request;
        json_builder_add_string(jb, "http_method", http_method_to_string(req->method));
        json_builder_add_string(jb, "url", req->uri);
        json_builder_add_string(jb, "hostname", req->host);
        json_builder_add_string(jb, "http_user_agent", req->user_agent);
        json_builder_add_string(jb, "http_content_type", req->content_type);
        if (req->content_length > 0) {
            json_builder_add_uint(jb, "length", req->content_length);
        }
    }

    if (tx->response) {
        http_response_t *resp = tx->response;
        json_builder_add_uint(jb, "status", resp->status_code);
        json_builder_add_string(jb, "http_refer", resp->reason_phrase);
        json_builder_add_string(jb, "server", resp->server);
    }

    json_builder_add_string(jb, "protocol", "HTTP/1.1");

    json_builder_end_object(jb);
    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

/* ============================================================================
 * DNS Output
 * ============================================================================ */

int json_output_dns(json_output_ctx_t *ctx, struct dns_transaction *tx,
                    struct flow *flow)
{
    if (!ctx || !tx) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", NULL);
    }

    json_builder_add_string(jb, "event_type", "dns");

    if (ctx->log_flow_info && flow) {
        json_add_flow_info(jb, flow);
    }

    /* DNS object */
    json_builder_add_string(jb, "dns", NULL);
    json_builder_start_object(jb);

    json_builder_add_string(jb, "type", tx->is_response ? "answer" : "query");
    json_builder_add_uint(jb, "id", tx->txid);

    if (tx->questions && tx->questions->qname) {
        json_builder_add_string(jb, "rrname", tx->questions->qname);
        json_builder_add_string(jb, "rrtype", dns_type_to_string(tx->questions->qtype));
    }

    if (tx->is_response) {
        json_builder_add_string(jb, "rcode", dns_rcode_to_string(tx->rcode));

        /* Add answers */
        if (tx->answers) {
            json_builder_add_string(jb, "answers", NULL);
            json_builder_start_array(jb);

            dns_rr_t *rr = tx->answers;
            for (uint16_t i = 0; i < tx->ancount && rr; i++, rr = rr->next) {
                json_builder_start_object(jb);
                json_builder_add_string(jb, "rrname", rr->name);
                json_builder_add_string(jb, "rrtype", dns_type_to_string(rr->type));
                json_builder_add_uint(jb, "ttl", rr->ttl);

                if (rr->type == DNS_TYPE_A) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, rr->parsed.a.addr, ip, sizeof(ip));
                    json_builder_add_string(jb, "rdata", ip);
                } else if (rr->type == DNS_TYPE_AAAA) {
                    char ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, rr->parsed.aaaa.addr, ip, sizeof(ip));
                    json_builder_add_string(jb, "rdata", ip);
                } else if (rr->parsed.domain) {
                    json_builder_add_string(jb, "rdata", rr->parsed.domain);
                }

                json_builder_end_object(jb);
            }

            json_builder_end_array(jb);
        }
    }

    json_builder_end_object(jb);
    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

/* ============================================================================
 * TLS Output
 * ============================================================================ */

int json_output_tls(json_output_ctx_t *ctx, struct tls_conn *tls_conn,
                    struct flow *flow)
{
    if (!ctx || !tls_conn) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", NULL);
    }

    json_builder_add_string(jb, "event_type", "tls");

    if (ctx->log_flow_info && flow) {
        json_add_flow_info(jb, flow);
    }

    /* TLS object */
    json_builder_add_string(jb, "tls", NULL);
    json_builder_start_object(jb);

    tls_client_hello_t *ch = tls_get_client_hello(tls_conn);
    tls_server_hello_t *sh = tls_get_server_hello(tls_conn);

    if (ch && ch->sni) {
        json_builder_add_string(jb, "sni", ch->sni);
    }

    if (ch) {
        json_builder_add_string(jb, "version", tls_version_to_string(ch->version));

        /* JA3 fingerprint */
        char ja3_hash[65];
        for (int i = 0; i < 16; i++) {
            snprintf(ja3_hash + i * 2, 3, "%02x", ch->ja3_hash[i]);
        }
        json_builder_add_string(jb, "ja3", ja3_hash);
        json_builder_add_string(jb, "ja3_string", ch->ja3_string);
    }

    if (sh) {
        json_builder_add_string(jb, "version_agreed", tls_version_to_string(sh->version));
        json_builder_add_string(jb, "cipher", sh->cipher_suite_name);

        /* JA3S fingerprint */
        char ja3s_hash[65];
        for (int i = 0; i < 16; i++) {
            snprintf(ja3s_hash + i * 2, 3, "%02x", sh->ja3s_hash[i]);
        }
        json_builder_add_string(jb, "ja3s", ja3s_hash);
    }

    json_builder_end_object(jb);
    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

/* ============================================================================
 * Flow Output
 * ============================================================================ */

int json_output_flow(json_output_ctx_t *ctx, struct flow *flow)
{
    if (!ctx || !flow) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", NULL);
    }

    json_builder_add_string(jb, "event_type", "flow");

    json_add_flow_info(jb, flow);

    json_builder_add_string(jb, "app_proto", app_proto_to_string(flow->alproto));

    if (flow->protoctx.tcp) {
        json_builder_add_uint(jb, "pkts_toserver", flow->protoctx.tcp->seg_cnt);
        json_builder_add_uint(jb, "bytes_toserver", flow->protoctx.tcp->byte_cnt);
    }

    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

/* ============================================================================
 * Stats Output
 * ============================================================================ */

int json_output_stats(json_output_ctx_t *ctx)
{
    if (!ctx) return -1;

    json_builder_t *jb = json_builder_create(0);
    if (!jb) return -1;

    json_builder_start_object(jb);

    if (ctx->log_timestamp) {
        json_add_timestamp(jb, "timestamp", NULL);
    }

    json_builder_add_string(jb, "event_type", "stats");

    json_builder_add_string(jb, "stats", NULL);
    json_builder_start_object(jb);
    json_builder_add_uint(jb, "events_written", ctx->events_written);
    json_builder_add_uint(jb, "bytes_written", ctx->bytes_written);
    json_builder_add_uint(jb, "rotations", ctx->rotations);
    json_builder_end_object(jb);

    json_builder_end_object(jb);

    int ret = json_output_write(ctx, json_builder_get_string(jb));
    json_builder_free(jb);
    return ret;
}

void json_output_get_stats(json_output_ctx_t *ctx, char *buf, size_t buflen)
{
    if (!ctx || !buf) return;

    snprintf(buf, buflen,
             "JSON Output: events=%lu bytes=%lu rotations=%lu errors=%lu",
             ctx->events_written, ctx->bytes_written,
             ctx->rotations, ctx->write_errors);
}
