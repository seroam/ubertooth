#include "ubertooth_le_monitoring.h"

void log_aa(lell_packet* pkt) {
	printf("Logging %06X\n", lell_get_access_address(pkt));
}