#include <stdio.h>
#include <rte_log.h>

#include "common.h"
#include "global_data.h"
#include "list.h"

#define RTE_LOGTYPE_DSCHED RTE_LOGTYPE_USER1

typedef enum ndf_lcore_job_type {
    LCORE_JOB_INIT,//初始化任务：在应用程序启动时执行一次的任务
    LCORE_JOB_LOOP,//循环任务：需要每个循环都执行的任务
    LCORE_JOB_SLOW,//慢速任务：需要定期执行但不需要每个循环都频繁执行的任务
    LCORE_JOB_TYPE_MAX//任务类型的最大值，用于边界检查
} ndf_lcore_job_t;

typedef void (*job_pt)(void* arg);

//每个核心上的job任务
struct ndf_lcore_job
{
    char name[32]; //任务名称
    void (*func)(void* arg); //具体执行任务的回调函数
    void *data;
    ndf_lcore_job_t type; //任务类型,enum枚举类型变量
    uint32_t skip_loops; //只针对LCORE_JOB_SLOW类型任务
    struct list_head list;
}__rte_cache_aligned;

struct ndf_lcore_job_array {
    struct ndf_lcore_job job;
    ndf_lcore_role_t role;
};

int ndf_scheduler_init(void);
int ndf_scheduler_term(void);

int ndf_lcore_start(int is_master);
const char *ndf_lcore_role_str(ndf_lcore_role_t role);
int ndf_lcore_job_register(struct ndf_lcore_job *lcore_job, ndf_lcore_role_t role);
int ndf_lcore_job_unregister(struct ndf_lcore_job *lcore_job, ndf_lcore_role_t role);