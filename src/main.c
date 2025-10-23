#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <getopt.h>

#include "dpdk.h"
#include "global_data.h"
#include "common.h"
#include "pidfile.h"
#include "scheduler.h"
#include "timer.h"
#include "netif.h"
#include "cfgfile.h"
#include "flow.h"
#include "stream_reassemble.h"
#include "proto_detect.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER1

#define LCORE_CONF_BUFFER_LEN 4096

static void dpdk_version_check(void)
{
#if RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0)
    rte_panic("The current netdefender requires dpdk-stable-24.11 or higher. "
            "Try old releases if you are using earlier dpdk versions.");
#endif
}

//LAST表示最后一个元素
#define NET_DEFENDER_MODULES {                                          \
        NET_DEFENDER_MODULE(MODULE_FIRST,       "scheduler",            \
                    ndf_scheduler_init, ndf_scheduler_term),            \
        NET_DEFENDER_MODULE(MODULE_GLOBAL_DATA, "global data",          \
                    global_data_init,    global_data_term),             \
        NET_DEFENDER_MODULE(MODULE_TIMER,       "timer",                \
                    ndf_timer_init,      ndf_timer_term),               \
        NET_DEFENDER_MODULE(MODULE_CFG,         "config file",          \
                    cfgfile_init,        cfgfile_term),                 \
        NET_DEFENDER_MODULE(MODULE_NETIF,       "netif",                \
                    netif_init,          netif_term),                   \
        NET_DEFENDER_MODULE(MODULE_LAST,        "last",                 \
                    NULL,                NULL)                          \
    }

#define NET_DEFENDER_MODULE(a, b, c, d)  a
enum net_defender_modules NET_DEFENDER_MODULES;
#undef NET_DEFENDER_MODULE

#define NET_DEFENDER_MODULE(a, b, c, d)  b
static const char *net_defender_modules[] = NET_DEFENDER_MODULES;
#undef NET_DEFENDER_MODULE

typedef int (*net_defender_module_init_pt)(void);
typedef int (*net_defender_module_term_pt)(void);

#define NET_DEFENDER_MODULE(a, b, c, d)  c
net_defender_module_init_pt net_defender_module_inits[] = NET_DEFENDER_MODULES;
#undef NET_DEFENDER_MODULE

#define NET_DEFENDER_MODULE(a, b, c, d)  d
net_defender_module_term_pt net_defender_module_terms[] = NET_DEFENDER_MODULES;

static void modules_init(void)
{
    int m, err;

    for (m = MODULE_FIRST; m <= MODULE_LAST; m++) {
        if (net_defender_module_inits[m]) {
            if ((err = net_defender_module_inits[m]()) != ENDF_OK) {
                rte_exit(EXIT_FAILURE, "failed to init %s: %s\n",
                         net_defender_modules[m], ndf_strerror(err));
            }
        }
    }
}

static void modules_term(void)
{
    int m, err;

    for (m = MODULE_LAST ; m >= MODULE_FIRST; m--) {
        if (net_defender_module_terms[m]) {
            if ((err = net_defender_module_terms[m]()) != ENDF_OK) {
                rte_exit(EXIT_FAILURE, "failed to term %s: %s\n",
                         net_defender_modules[m], ndf_strerror(err));
            }
        }
    }
}

static void netdefender_usage(const char *prgname)
{
    printf("\nUsage: %s ", prgname);
    printf("netdefender application options:\n"
            "   -v, --version           display netdefender version info\n"
            "   -c, --conf FILE         specify config file for netdefender\n"
            "   -p, --pid-file FILE     specify pid file of netdefender process\n"
            "   -x, --ipc-file FILE     specify unix socket file for ipc communication between netdefender and Tools\n"
            "   -h, --help              display netdefender help info\n"
    );
}

static int parse_app_args(int argc, char **argv)
{
    const char *short_options = "vhc:p:x:";
    char *prgname = argv[0];
    int c, ret = -1;

    const int old_optind = optind;
    const int old_optopt = optopt;
    char * const old_optarg = optarg;

    struct option long_options[] = {
        {"version", 0, NULL, 'v'},
        {"conf", required_argument, NULL, 'c'},
        {"pid-file", required_argument, NULL, 'p'},
        {"ipc-file", required_argument, NULL, 'x'},
        {"help", 0, NULL, 'h'},
        {NULL, 0, 0, 0}
    };

    optind = 1;

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                fprintf(stderr, "netdefender version: %s, build on %s\n",
                        NET_DEFENDER_VERSION,
                        NET_DEFENDER_BUILD_DATE);
                exit(EXIT_SUCCESS);
            case 'c':
                netdefender_conf_file=optarg;
                break;
            case 'p':
                netdefender_pid_file=optarg;
                break;
            case 'x':
                netdefender_ipc_file=optarg;
                break;
            case 'h':
                netdefender_usage(prgname);
                exit(EXIT_SUCCESS);
            case '?':
            default:
                netdefender_usage(prgname);
                exit(EXIT_FAILURE);
        }
    }

    if (optind > 0)
        argv[optind-1] = prgname;

    ret = optind - 1;

    /* restore getopt lib */
    optind = old_optind;
    optopt = old_optopt;
    optarg = old_optarg;

    /* check */
    if (!netdefender_conf_file)
        netdefender_conf_file="/etc/netdefender.conf";
    if (!netdefender_pid_file)
        netdefender_pid_file="/var/run/netdefender.pid";
    if (!netdefender_ipc_file)
        netdefender_ipc_file="/var/run/netdefender.ipc";

    g_version = version_parse(NET_DEFENDER_VERSION);

    return ret;
}

int main(int argc, char *argv[])
{
    //1.check dpdk version
    dpdk_version_check();

    int err, nports;
    portid_t pid;
    struct netif_port *dev;

    char pql_conf_buf[LCORE_CONF_BUFFER_LEN];
    int pql_conf_buf_len = LCORE_CONF_BUFFER_LEN;

    /**
     * add application agruments parse before EAL ones.
     * use it like the following:
     * ./dpdk_nids -v
     * OR
     * ./dpdk_nids -- -n 4 -l 0-11 (if you want to use eal arguments)
     */
    err = parse_app_args(argc, argv);
    if (err < 0) {
        fprintf(stderr, "fail to parse application options\n");
        exit(EXIT_FAILURE);
    }
    argc -= err, argv += err;

    /* check if NetDefender is running or not*/
    if (netdefender_running(netdefender_pid_file)) {
        fprintf(stderr, "netdefender is already running\n");
        exit(EXIT_FAILURE);
    }

    netdefender_state_set(NET_DEFENDER_STATE_INIT);
    if(get_numa_nodes() > NDF_MAX_SOCKET){
        fprintf(stderr, "NDF_MAX_SOCKET is smaller than system numa nodes!\n");
        return -1;
    }

    // 初始化DPDK环境
    err = rte_eal_init(argc, argv);
    if(err < 0){
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
        goto end;
    }
    
    //初始化定时器系统
    rte_timer_subsystem_init();

    //初始化各个子模块
    modules_init();

    // 初始化Flow管理系统
    RTE_LOG(INFO, MAIN, "Initializing flow management system...\n");
    if (flow_init(65536, 1000000) != 0) {  /* 64K hash buckets, 1M max flows */
        rte_exit(EXIT_FAILURE, "Failed to initialize flow management\n");
    }
    RTE_LOG(INFO, MAIN, "Flow management system initialized\n");

    // 初始化TCP流重组系统
    RTE_LOG(INFO, MAIN, "Initializing TCP stream reassembly...\n");
    stream_config_t stream_cfg = {
        .max_buffer_size = 256 * 1024,  /* 256 KB per stream */
        .max_segments = 100,            /* Max 100 out-of-order segments */
        .default_policy = OS_POLICY_LINUX,  /* Linux: favor new data on overlap */
    };
    if (stream_reassemble_init(&stream_cfg) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize stream reassembly\n");
    }
    RTE_LOG(INFO, MAIN, "TCP stream reassembly initialized (Linux policy)\n");

    // 初始化协议检测系统
    RTE_LOG(INFO, MAIN, "Initializing protocol detection...\n");
    proto_detect_config_t proto_cfg = {
        .max_inspect_depth = 4096,      /* 4KB inspection depth */
        .enable_port_detection = true,
        .enable_pattern_matching = true,
        .enable_probing_parsers = true,
    };
    if (proto_detect_init(&proto_cfg) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize protocol detection\n");
    }
    RTE_LOG(INFO, MAIN, "Protocol detection initialized\n");

    // 获取当前设备的可用端口数
    nports = ndf_rte_eth_dev_count();
    for(pid = 0; pid < nports; pid++){
        dev = netif_port_get(pid);
        if(!dev){
            RTE_LOG(INFO, MAIN, "netif port of portid %d not found, likely kni portid, skip ...\n", pid);
            continue;
        }

        err = netif_port_start(dev);
        if(err != ENDF_OK){
            RTE_LOG(WARNING, MAIN, "Start %s failed, skipping ...\n", dev->name);   
        }
    }

    /* print port-queue-lcore relation */
    netif_print_lcore_conf(pql_conf_buf, &pql_conf_buf_len, true, 0);
    RTE_LOG(INFO, MAIN, "port-queue-lcore relation array: \n%s\n",
            pql_conf_buf);

    /* start slave worker threads */
    RTE_LOG(INFO, MAIN, "Starting slave worker threads...\n");
    ndf_lcore_start(0);
    RTE_LOG(INFO, MAIN, "Slave worker threads started\n");

    /* write pid file */
    if(!pidfile_write(netdefender_pid_file, getpid())){
        RTE_LOG(ERR, MAIN, "Failed to write pid file\n");
        goto end;
    }
    RTE_LOG(INFO, MAIN, "PID file written successfully\n");

    netdefender_state_set(NET_DEFENDER_STATE_NORMAL);

    /* start control plane thread loop */
    RTE_LOG(INFO, MAIN, "Starting master control plane thread...\n");
    ndf_lcore_start(1);
    RTE_LOG(INFO, MAIN, "Master control plane thread returned (this should not happen!)\n");
    
    // TODO: 初始化检测引擎
    
    // TODO: 主事件循环
end:
    RTE_LOG(INFO, MAIN, "Program ending, cleaning up...\n");
    netdefender_state_set(NET_DEFENDER_STATE_FINISH);

    /* Cleanup flow management */
    flow_cleanup();

    /* Cleanup stream reassembly */
    stream_reassemble_cleanup();

    modules_term();

    return 0;
}
