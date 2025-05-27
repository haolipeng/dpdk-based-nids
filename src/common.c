#include "common.h"

static dpvs_state_t g_dpvs_tate = DPVS_STATE_STOP;

void dpvs_state_set(dpvs_state_t stat)
{
    g_dpvs_tate = stat;
}

dpvs_state_t dpvs_state_get(void)
{
    return g_dpvs_tate;
}