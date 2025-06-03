#include "scheduler.h"

int ndf_scheduler_init(void)
{
    return ENDF_OK;
}

int ndf_scheduler_term(void)
{
    return ENDF_OK;
}

const char *dpvs_lcore_role_str(ndf_lcore_role_t role)
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