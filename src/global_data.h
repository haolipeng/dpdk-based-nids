#ifndef GLOBAL_DATA_H
#define GLOBAL_DATA_H

#include <string.h>
#include <stdlib.h>

extern char *dpvs_pid_file;
extern char *dpvs_ipc_file;
extern char *dpvs_conf_file;

extern unsigned int g_version;

int version_parse(const char *strver);
#endif
