#include "common.h"

static netdefender_state_t g_netdefender_tate = NET_DEFENSER_STATE_STOP;

void netdefender_state_set(netdefender_state_t stat)
{
    g_netdefender_tate = stat;
}

netdefender_state_t netdefender_state_get(void)
{
    return g_netdefender_tate;
}