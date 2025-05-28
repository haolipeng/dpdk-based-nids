#include <assert.h>
#include <stdio.h>
#include "pidfile.h"

/* Create the running pidfile */
int pidfile_write(const char *pid_file, int pid)
{
    assert(pid_file && pid > 0);

    FILE *pidfile = fopen(pid_file, "w");

    if (!pidfile) {
        syslog(LOG_INFO, "%s: Cannot open %s pid file\n", __func__, pid_file);
        return 0;
    }

    fprintf(pidfile, "%d\n", pid);
    fclose(pidfile);
    return 1;
}

/* Remove the running pidfile */
void pidfile_rm(const char *pid_file)
{
    if (pid_file)
        unlink(pid_file);
}

/* Return the running state */
bool netdefender_running(const char *pid_file)
{
    FILE *pidfile = fopen(pid_file, "r");
    pid_t pid;

    /* pidfile not exist */
    if (!pidfile)
        return false;

    if (fscanf(pidfile, "%d", &pid) != 1) {
        fclose(pidfile);
        return false;
    }
    fclose(pidfile);

    /* remove pidfile if no process attached to it */
    if (kill(pid, 0)) {
        syslog(LOG_INFO, "%s: Remove a zombie pid file %s\n", __func__, pid_file);
        pidfile_rm(pid_file);
        return false;
    }

    return true;
}

