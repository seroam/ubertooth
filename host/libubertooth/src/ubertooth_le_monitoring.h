#ifndef __UBERTOOTH_LE_MONITORING_H
#define __UBERTOOTH_LE_MONITORING_H

#include <time.h>

#include "ubertooth.h"

typedef struct {
	time_t timestamp;
	uint32_t aa;
	uint32_t count;
} aa_log_entry_t;

typedef struct {
	size_t num_entries;
	aa_log_entry_t* log;
} aa_log_t;
aa_log_t aa_log;
#define AA_LOG_SIZE 1000

void init_aa_log();
void log_aa(lell_packet* pkt);
#endif /* __UBERTOOTH_LE_MONITORING_H */

