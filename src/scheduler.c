#include "scheduler.h"

/* Note: lockless, lcore_job can only be register on initialization stage and
 *       unregistered on cleanup stage.
 */
static struct list_head ndf_lcore_jobs[LCORE_ROLE_MAX][LCORE_JOB_TYPE_MAX];

int ndf_scheduler_init(void)
{
    return ENDF_OK;
}

int ndf_scheduler_term(void)
{
    return ENDF_OK;
}

int dpvs_lcore_job_register(struct ndf_lcore_job *lcore_job, ndf_lcore_role_t role)
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