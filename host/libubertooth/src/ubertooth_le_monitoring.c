#include "ubertooth_le_monitoring.h"

void init_aa_log() {
	printf("sizeof(aa_log_entry_t)=%u\n", sizeof(aa_log_entry_t));
	aa_log.log = (aa_log_entry_t*)malloc(sizeof(aa_log_entry_t) * AA_LOG_SIZE);
}

void destroy_aa_log() {
	free(aa_log.log);
	aa_log.log = NULL;
}

void log_aa(lell_packet* pkt) {

	time_t timestamp = time(NULL);
	printf("Logging %06X\n", lell_get_access_address(pkt));
	printf("sizeof(aa_log.log)=%u\n", sizeof(aa_log.log));
}