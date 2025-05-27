#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>

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
    DPVS_STATE_STOP = 1,
    DPVS_STATE_INIT,
    DPVS_STATE_NORMAL,
    DPVS_STATE_FINISH,
} dpvs_state_t;

void dpvs_state_set(dpvs_state_t stat);
dpvs_state_t dpvs_state_get(void);

#endif
