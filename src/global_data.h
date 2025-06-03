#ifndef GLOBAL_DATA_H
#define GLOBAL_DATA_H

#include <string.h>
#include <stdlib.h>

#include "common.h"

typedef enum ndf_lcore_role_type {
    LCORE_ROLE_IDLE,//空闲状态：表示线程未分配任何角色，未被分配任何角色
    LCORE_ROLE_MASTER,//主控线程：负责管理整个应用程序的运行，负责配置更新、状态监控、控制面处理等
    LCORE_ROLE_FWD_WORKER,//转发工作线程：负责处理数据包的转发，负责数据包接收、路由查找、转发等
    LCORE_ROLE_ISOLRX_WORKER,//隔离接收工作线程：负责接收隔离数据包，专门负责数据包的接收，与处理逻辑分离，提升接收效率
    LCORE_ROLE_KNI_WORKER,//KNI工作线程：负责处理KNI相关的任务，处理与linux内核的交互
    LCORE_ROLE_MAX//角色类型的最大值，用于边界检查
} ndf_lcore_role_t;

extern ndf_lcore_role_t g_lcore_role[NDF_MAX_LCORE];
extern int g_lcore_index2id[NDF_MAX_LCORE];
extern int g_lcore_id2index[NDF_MAX_LCORE];
extern int g_lcore_num;

extern char *netdefender_pid_file;
extern char *netdefender_ipc_file;
extern char *netdefender_conf_file;

extern unsigned int g_version;

int version_parse(const char *strver);

#endif
