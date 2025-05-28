#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <getopt.h>

#include "dpdk.h"
#include "global_data.h"
#include "common.h"
#include "pidfile.h"
static void dpdk_version_check(void)
{
#if RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0)
    rte_panic("The current netdefender requires dpdk-stable-24.11 or higher. "
            "Try old releases if you are using earlier dpdk versions.");
#endif
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
                        NET_DEFENSER_VERSION,
                        NET_DEFENSER_BUILD_DATE);
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

    g_version = version_parse(NET_DEFENSER_VERSION);

    return ret;
}

/**
 * NetDefender主程序入口
 * 基于DPDK的高性能网络入侵检测系统
 */
int main(int argc, char *argv[])
{
    printf("Hello World! 欢迎使用NetDefender - 基于DPDK的高性能网络入侵检测系统\n");
    
    dpdk_version_check();

    int err;
    //int err, nports;
    //portid_t pid;
    //struct netif_port *dev;
    //struct timeval tv;

    err = parse_app_args(argc, argv);
    if (err < 0) {
        fprintf(stderr, "fail to parse application options\n");
        exit(EXIT_FAILURE);
    }
    argc -= err, argv += err;

    /* check if NetDefender is running */
    if (netdefender_running(netdefender_pid_file)) {
        fprintf(stderr, "netdefender is already running\n");
        exit(EXIT_FAILURE);
    }

    netdefender_state_set(NET_DEFENSER_STATE_INIT);
    // TODO: 初始化DPDK环境
    
    // TODO: 配置和启动数据包捕获
    
    // TODO: 初始化检测引擎
    
    // TODO: 主事件循环
    
    return 0;
}
