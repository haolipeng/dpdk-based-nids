#include "common.h"
#include <numa.h>

static netdefender_state_t g_netdefender_tate = NET_DEFENSER_STATE_STOP;

void netdefender_state_set(netdefender_state_t stat)
{
    g_netdefender_tate = stat;
}

netdefender_state_t netdefender_state_get(void)
{
    return g_netdefender_tate;
}

int get_numa_nodes(void){
    int numa_nodes = 0;

    if(numa_available() < 0){
        numa_nodes = 0;
    }
    else{
        numa_nodes = numa_max_node();
    }
    return (numa_nodes + 1);
}

struct ndf_err_tab {
    int errcode;
    const char *errmsg;
};

const char *ndf_strerror(int err)
{
    /* TODO: "per-lcorelize" it */
    static const struct ndf_err_tab err_tab[] = {
        { ENDF_OK,             "OK" },
        { ENDF_INVAL,          "invalid parameter" },
        { ENDF_NOMEM,          "no memory" },
        { ENDF_EXIST,          "already exist" },
        { ENDF_NOTEXIST,       "not exist" },
        { ENDF_INVPKT,         "invalid packet" },
        { ENDF_DROP,           "packet dropped" },
        { ENDF_NOPROT,         "no protocol" },
        { ENDF_NOROUTE,        "no route" },
        { ENDF_DEFRAG,         "defragment error" },
        { ENDF_FRAG,           "fragment error" },
        { ENDF_DPDKAPIFAIL,    "failed dpdk api" },
        { ENDF_IDLE,           "nothing to do" },
        { ENDF_BUSY,           "resource busy" },
        { ENDF_NOTSUPP,        "not support" },
        { ENDF_RESOURCE,       "no resource" },
        { ENDF_OVERLOAD,       "overloaded" },
        { ENDF_NOSERV,         "no service" },
        { ENDF_DISABLED,       "disabled" },
        { ENDF_NOROOM,         "no room" },
        { ENDF_NONEALCORE,     "non-EAL thread lcore" },
        { ENDF_CALLBACKFAIL,   "callback failed" },
        { ENDF_IO,             "I/O error" },
        { ENDF_MSG_FAIL,       "msg callback failed"},
        { ENDF_MSG_DROP,       "msg dropped"},
        { ENDF_PKTSTOLEN,      "stolen packet"},
        { ENDF_SYSCALL,        "system call failed"},
        { ENDF_NODEV,          "no such device"},

        { ENDF_KNICONTINUE,    "kni to continue"},
        { ENDF_INPROGRESS,     "in progress"},
    };
    size_t i;

    for (i = 0; i < NELEMS(err_tab); i++) {
        if (err == err_tab[i].errcode)
            return err_tab[i].errmsg;
    }

    return "<unknow>";
}