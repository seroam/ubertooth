#include "ubertooth_le_monitoring.h"

void init_aa_log() {
	printf("sizeof(aa_log_entry_t)=%u\n", sizeof(aa_log_entry_t));
	aa_log.num_entries = 0;
	aa_log.log = (aa_log_entry_t*)malloc(sizeof(aa_log_entry_t) * AA_LOG_SIZE);
	memset(aa_log.log, 0, sizeof(aa_log_entry_t) * AA_LOG_SIZE);
}

void destroy_aa_log() {
	free(aa_log.log);
	aa_log.log = NULL;
}

void log_aa(lell_packet* pkt) {

	time_t timestamp = time(NULL);
	int aa = lell_get_access_address(pkt);

	
	for (size_t i = 0; i < AA_LOG_SIZE; ++i) {
		if (aa_log.log[i].aa == aa) {
			aa_log.log[i].timestamp = timestamp;
			
			if (++aa_log.log[i].count > 4) {
				printf("\rAA=%06X timestamp=%u count=%u\n", aa, timestamp, aa_log.log[i].count);
			}

			return;
		}
	}

	if (aa_log.num_entries < AA_LOG_SIZE) {
		for (size_t i = 0; i < AA_LOG_SIZE; ++i) {
			if (aa_log.log[i].aa == 0) {
				aa_log.log[i].aa = aa;
				aa_log.log[i].timestamp = timestamp;
				++aa_log.log[i].count;

				++aa_log.num_entries;
				return;
			}
		}
	}
	else {
		// TODO: FREE SOME SPACE
		printf("LOG FULL\n");
	}

}