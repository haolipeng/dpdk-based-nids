#include <stdio.h>

#include "common.h"
#include "global_data.h"

int ndf_scheduler_init(void);
int ndf_scheduler_term(void);

const char *dpvs_lcore_role_str(ndf_lcore_role_t role);