#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "global_data.h"
#include "common.h"

char *dpvs_pid_file;
char *dpvs_ipc_file;
char *dpvs_conf_file;

unsigned int g_version = 0;

int version_parse(const char *strver)
{
    size_t i, j = 0;
    size_t len;
    unsigned int version = 0, mask = 0xFF;
    char *sver;

    if (strver[0] == 'v' || strver[0] == 'V') {
        sver = strdup(&strver[1]);
        len = strlen(&strver[1]);
    } else {
        sver = strdup(strver);
        len = strlen(strver);
    }

    if (unlikely(sver == NULL))
        return 0;

    for (i = 0; i < len && mask < 0xFFFFFF; i++) {
        if ('.' == sver[i] || '-' == sver[i]) {
            sver[i] = '\0';
            version = ((version << 8) | atoi(&sver[j])) & mask;
            mask |= mask << 8;
            j = i + 1;
            continue;
        }
        if (!isdigit(sver[i]))
            break;
    }
    version = ((version << 8) | atoi(&sver[j])) & mask;

    free(sver);
    return version;
}
