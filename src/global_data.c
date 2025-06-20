#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <rte_cycles.h>

#include "global_data.h"
#include "common.h"

char *netdefender_pid_file;
char *netdefender_ipc_file;
char *netdefender_conf_file;

lcoreid_t g_kni_lcore_id = 0;
lcoreid_t g_master_lcore_id;

RTE_DEFINE_PER_LCORE(uint32_t, g_ndf_poll_tick);
uint64_t g_cycles_per_sec;//每秒的时钟周期数

ndf_lcore_role_t g_lcore_role[NDF_MAX_LCORE];
int g_lcore_index2id[NDF_MAX_LCORE];//建立逻辑核心id和数组索引之间的关系
int g_lcore_id2index[NDF_MAX_LCORE];//建立数组索引和逻辑核心id之间的关系
int g_lcore_num; //记录使用的逻辑核心的数量
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

int global_data_init(void)
{
    int i;

    g_cycles_per_sec = rte_get_timer_hz();
    g_lcore_num = 0;

    //初始化逻辑核心角色、索引和id
    for (i = 0; i < NDF_MAX_LCORE; i++) {
        g_lcore_role[i] = LCORE_ROLE_IDLE;
        g_lcore_index2id[i] = -1;
        g_lcore_id2index[i] = -1;
    }

    return ENDF_OK;
}

int global_data_term(void)
{
    return ENDF_OK;
}
