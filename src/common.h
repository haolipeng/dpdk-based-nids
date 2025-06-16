#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rte_lcore.h>

// NDF_MAX_SOCKET 现在通过 CMake 构建系统定义
#ifndef NDF_MAX_SOCKET
#define NDF_MAX_SOCKET 4  // 备用默认值
#endif

#ifndef NDF_MAX_LCORE
#define NDF_MAX_LCORE RTE_MAX_LCORE
#endif

typedef uint32_t sockoptid_t;

#ifndef NELEMS
#define NELEMS(a)       (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef min
#define min(x,y) ({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
    (void) (&_x == &_y);    \
    _x < _y ? _x : _y; })
#endif

#ifndef max
#define max(x,y) ({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
    (void) (&_x == &_y);    \
    _x > _y ? _x : _y; })
#endif

#ifndef min_t
#define min_t(type, a, b) min(((type) a), ((type) b))
#endif
#ifndef max_t
#define max_t(type, a, b) max(((type) a), ((type) b))
#endif

#ifndef __be32
typedef uint32_t    __be32;
#endif

#ifndef __be16
typedef uint16_t    __be16;
#endif

#ifndef __u8
typedef uint8_t     __u8;
#endif

#ifndef __u16
typedef uint16_t    __u16;
#endif

#ifndef __u32
typedef uint32_t    __u32;
#endif

#ifndef lcoreid_t
typedef uint8_t lcoreid_t;
#endif

#ifndef portid_t
typedef uint16_t portid_t;
#endif

#ifndef queueid_t
typedef uint16_t queueid_t;
#endif

// 定义likely/unlikely宏用于分支预测优化
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

typedef enum {
    NET_DEFENDER_STATE_STOP = 1,
    NET_DEFENDER_STATE_INIT,
    NET_DEFENDER_STATE_NORMAL,
    NET_DEFENDER_STATE_FINISH,
} netdefender_state_t;

void netdefender_state_set(netdefender_state_t stat);
netdefender_state_t netdefender_state_get(void);

const char *ndf_strerror(int err);

enum {
    ENDF_OK            = 0,
    ENDF_INVAL         = -1,       /* invalid parameter */
    ENDF_NOMEM         = -2,       /* no memory */
    ENDF_EXIST         = -3,       /* already exist */
    ENDF_NOTEXIST      = -4,       /* not exist */
    ENDF_INVPKT        = -5,       /* invalid packet */
    ENDF_DROP          = -6,       /* packet dropped */
    ENDF_NOPROT        = -7,       /* no protocol */
    ENDF_NOROUTE       = -8,       /* no route */
    ENDF_DEFRAG        = -9,       /* defragment error */
    ENDF_FRAG          = -10,      /* fragment error */
    ENDF_DPDKAPIFAIL   = -11,      /* DPDK error */
    ENDF_IDLE          = -12,      /* nothing to do */
    ENDF_BUSY          = -13,      /* resource busy */
    ENDF_NOTSUPP       = -14,      /* not support */
    ENDF_RESOURCE      = -15,      /* no resource */
    ENDF_OVERLOAD      = -16,      /* overloaded */
    ENDF_NOSERV        = -17,      /* no service */
    ENDF_DISABLED      = -18,      /* disabled */
    ENDF_NOROOM        = -19,      /* no room */
    ENDF_NONEALCORE    = -20,      /* non-eal thread lcore */
    ENDF_CALLBACKFAIL  = -21,      /* callbacks fail */
    ENDF_IO            = -22,      /* I/O error */
    ENDF_MSG_FAIL      = -23,      /* msg callback failed */
    ENDF_MSG_DROP      = -24,      /* msg callback dropped */
    ENDF_PKTSTOLEN     = -25,      /* stolen packet */
    ENDF_SYSCALL       = -26,      /* system call failed */
    ENDF_NODEV         = -27,      /* no such device */

    /* positive code for non-error */
    ENDF_KNICONTINUE   = 1,        /* KNI to continue */
    ENDF_INPROGRESS    = 2,        /* in progress */
};

int get_numa_nodes(void);
bool is_power2(int num, int offset, int *lower);

#endif
