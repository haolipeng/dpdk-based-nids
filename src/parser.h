#ifndef __PARSER_H__
#define __PARSER_H__

#include <stdbool.h>
#include "vector.h"

#define RTE_LOGTYPE_CFG_FILE RTE_LOGTYPE_USER1
typedef enum {
    KW_TYPE_INIT = 1, /* keyword used in init stage only */
    KW_TYPE_NORMAL = 2, /* keyword used in both init and normal stage */
} keyword_type_t;

typedef void (*keyword_callback_t)(vector_t);

/* global definitions */
#define CFG_FILE_EOB "}"
#define CFG_FILE_MAX_BUF_SZ 1024

/* exported global vars */
extern vector_t g_keywords;
extern FILE *g_current_stream;
extern bool g_reload;

/* keyword definition */
struct keyword {
    char *str;
    keyword_callback_t handler;
    vector_t sub;
};

/* interfaces */
void keyword_alloc(vector_t keywords_vec, char *str, keyword_callback_t handler);
void keyword_alloc_sub(vector_t keywords_vec, char *str, keyword_callback_t handler);
void free_keywords(vector_t keywords);

void install_sublevel(void);
void install_sublevel_end(void);
void install_keyword_root(char *str, keyword_callback_t handler);
void install_keyword(char *str, keyword_callback_t handler, keyword_type_t type);

void *set_value(vector_t tokens);
void init_data(char *conf_file, vector_t (*init_keywords)(void));
#endif