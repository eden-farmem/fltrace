/*
 * dump.h - support for dumping a snapshot of remote memory state
 */

#ifndef __DUMP_H__
#define __DUMP_H__

#include "rmem/common.h"

extern bool dump_rmem_state_and_exit;
void dump_rmem_state();

#endif