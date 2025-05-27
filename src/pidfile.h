#ifndef __PIDFILE_H__
#define __PIDFILE_H__

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <stdbool.h>

/* lock file */
#define RTE_LOGTYPE_PIDFILE RTE_LOGTYPE_USER1

int pidfile_write(const char *pid_file, int pid);

void pidfile_rm(const char *pid_file);

bool dpvs_running(const char *pid_file);

#endif
