#include "scheduler.h"

/* Note: lockless, lcore_job can only be register on initialization stage and
 *       unregistered on cleanup stage.
 */
static struct list_head ndf_lcore_jobs[LCORE_ROLE_MAX][LCORE_JOB_TYPE_MAX];

int ndf_scheduler_init(void)
{
    int ii, jj;
    for (ii = 0; ii < LCORE_ROLE_MAX; ii++) {
        for (jj = 0; jj < LCORE_JOB_TYPE_MAX; jj++) {
            INIT_LIST_HEAD(&ndf_lcore_jobs[ii][jj]);
        }
    }
    return ENDF_OK;
}

int ndf_scheduler_term(void)
{
    return ENDF_OK;
}

void ndf_lcore_job_init(struct ndf_lcore_job *job, char *name,
                         ndf_lcore_job_t type, job_pt func,
                         uint32_t skip_loops)
{
    if (!job) {
        return;
    }

    job->type = type;
    job->func = func;
    job->skip_loops = skip_loops;
    snprintf(job->name, sizeof(job->name) - 1, "%s", name);
}

int ndf_lcore_job_register(struct ndf_lcore_job *lcore_job, ndf_lcore_role_t role)
{
    struct ndf_lcore_job *cur;

    if (unlikely(NULL == lcore_job || role >= LCORE_ROLE_MAX))
        return ENDF_INVAL;

    if (unlikely(LCORE_JOB_SLOW == lcore_job->type && lcore_job->skip_loops <= 0))
        return ENDF_INVAL;

    list_for_each_entry(cur, &ndf_lcore_jobs[role][lcore_job->type], list) {
        if (cur == lcore_job) {
            return ENDF_EXIST;
        }
    }

    list_add_tail(&lcore_job->list, &ndf_lcore_jobs[role][lcore_job->type]);

    return ENDF_OK;
}

int ndf_lcore_job_unregister(struct ndf_lcore_job *lcore_job, ndf_lcore_role_t role)
{
    struct ndf_lcore_job *cur;

    if (unlikely(NULL == lcore_job || role >= LCORE_ROLE_MAX))
        return ENDF_INVAL;

    list_for_each_entry(cur, &ndf_lcore_jobs[role][lcore_job->type], list) {
        if (cur == lcore_job) {
            list_del_init(&cur->list);
            return ENDF_OK;
        }
    }

    return ENDF_NOTEXIST;
}

const char *ndf_lcore_role_str(ndf_lcore_role_t role)
{
    static const char *role_str_tab[] = {
        [LCORE_ROLE_IDLE]          = "lcre_role_idle",
        [LCORE_ROLE_MASTER]        = "lcre_role_master",
        [LCORE_ROLE_FWD_WORKER]    = "lcre_role_fwd_worker",
        [LCORE_ROLE_ISOLRX_WORKER] = "lcre_role_isolrx_worker",
        [LCORE_ROLE_KNI_WORKER]    = "lcore_role_kni_worker",
        [LCORE_ROLE_MAX]           = "lcre_role_null"
    };

    if (likely(role >= LCORE_ROLE_IDLE && role <= LCORE_ROLE_MAX))
        return role_str_tab[role];
    else
        return "lcore_role_unknown";
}

static inline void do_lcore_job(struct ndf_lcore_job* job){
    job->func(job->data);
}

static int ndf_job_loop(/* void* arg */)
{
    struct ndf_lcore_job* job;
    lcoreid_t cid = rte_lcore_id();
    ndf_lcore_role_t role = g_lcore_role[cid];//每一个核心都有自己的角色

    if(cid >= NDF_MAX_LCORE){
        return ENDF_OK;
    }

    /* skip irrelative job loops */
    if (role == LCORE_ROLE_MAX)
        return ENDF_INVAL;

    if (role == LCORE_ROLE_IDLE)
        return ENDF_IDLE;

    RTE_LOG(INFO, DSCHED, "lcore %02d enter %s loop\n", cid, ndf_lcore_role_str(role));

    /* do init job */
    list_for_each_entry(job, &ndf_lcore_jobs[role][LCORE_JOB_INIT], list){
        do_lcore_job(job);
    }

    while(1){
        ++this_poll_tick;

        /* do normal job */
        list_for_each_entry(job, &ndf_lcore_jobs[role][LCORE_JOB_LOOP], list) {
            do_lcore_job(job);
        }

        /* do slow job */
        list_for_each_entry(job, &ndf_lcore_jobs[role][LCORE_JOB_SLOW], list){
            if (this_poll_tick % job->skip_loops == 0) {
                do_lcore_job(job);
            }
        }
    }

    return ENDF_OK;
}

int ndf_lcore_start(int is_master)
{
    if(is_master){
        return ndf_job_loop(NULL);
    }

    return rte_eal_mp_remote_launch(ndf_job_loop, NULL, SKIP_MAIN);
}