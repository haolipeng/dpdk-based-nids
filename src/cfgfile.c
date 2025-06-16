#include <unistd.h>
#include <signal.h>
#include "dpdk.h"
#include "cfgfile.h"
#include "scheduler.h"
#include "netif.h"
#include "vector.h"
#include "parser.h"

#define RTE_LOGTYPE_CFG_FILE RTE_LOGTYPE_USER1

typedef void (*sighandler_t)(int);

bool g_reload = false;
extern vector_t g_keywords;

static void keyword_value_init(void)
{
    /* init keywords value here */

    netif_keyword_value_init();
    //timer_keyword_value_init();
}

static vector_t install_keywords(void)
{
    /* install configuration keywords here */
    //install_global_keywords();

    install_netif_keywords();
    //install_timer_keywords();//TODO:

    return g_keywords;
}

static inline void load_conf_file(char *cfg_file)
{
    keyword_value_init();
    init_data(cfg_file, install_keywords);
}

static inline void sighup(void)
{
    g_reload = true;
}

static void try_reload(void *dump)
{
    if (unlikely(g_reload)) {
        g_reload = false;
        /* using default configuration file */
        load_conf_file(NULL);
    }
}

static void sig_callback(int sig)
{
    switch(sig) {
        case SIGHUP:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGHUP.\n");
            sighup();
            break;
        case SIGINT:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGINT.\n");
            break;
        case SIGQUIT:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGQUIT.\n");
            break;
        case SIGTERM:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGTERM.\n");
            break;
        default:
            RTE_LOG(INFO, CFG_FILE, "Unkown signal type %d.\n", sig);
            break;
    }
}

static struct ndf_lcore_job reload_job = {
    .name = "cfgfile_reload",
    .type = LCORE_JOB_LOOP,
    .func = try_reload,
};

int cfgfile_init(void)
{
    int ret;
    struct sigaction sig;

    netif_cfgfile_init();

    /* register SIGHUP signal handler */
    memset(&sig, 0, sizeof(struct sigaction));
    sig.sa_handler = sig_callback;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    ret = sigaction(SIGHUP, &sig, NULL);
    if (ret < 0) {
        RTE_LOG(ERR, CFG_FILE, "%s: signal handler register failed\n", __func__);
        return ENDF_SYSCALL;
    }

    /* module initialization */
    // TODO:comment by haolipeng 2025-06-16
    /*if ((ret = global_conf_init()) != ENDF_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: global configuration initialization failed\n",
                __func__);
        return ret;
    }*/

    /* load configuration file on start */
    g_reload = true;
    try_reload(NULL);

    ret = ndf_lcore_job_register(&reload_job, LCORE_ROLE_MASTER);
    if (ret != ENDF_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: fail to register cfgfile_reload job\n", __func__);
        return ret;
    }

    return ENDF_OK;
}

int cfgfile_term(void)
{
    int ret;
    /* module termination */
    // TODO:comment by haolipeng 2025-06-16
    /*if ((ret = global_conf_term()) != ENDF_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: global configuration termination failed\n",
                __func__);
        return ret;
    }*/

    ret = ndf_lcore_job_unregister(&reload_job, LCORE_ROLE_MASTER);
    if (ret != ENDF_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: fail to unregister cfgfile_reload job\n", __func__);
        return ret;
    }

    return ENDF_OK;
}
