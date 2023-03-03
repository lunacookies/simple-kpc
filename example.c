#include "simple_kpc.h"
#include <stdint.h>
#include <stdlib.h>

void your_code_here(void)
{
	for (uint32_t i = 0; i < 100000; i++) {
		uint32_t r = arc4random();
		if (r % 2)
			arc4random();
	}
}

int main()
{
	sk_init();

	sk_events *e = sk_events_create();
	sk_events_push(e, "cycles", "FIXED_CYCLES");
	sk_events_push(e, "instructions", "FIXED_INSTRUCTIONS");
	sk_events_push(e, "branches", "INST_BRANCH");
	sk_events_push(e, "branch misses", "BRANCH_MISPRED_NONSPEC");
	sk_events_push(e, "subroutine calls", "INST_BRANCH_CALL");

	sk_in_progress_measurement *m = sk_start_measurement(e);
	your_code_here();
	sk_finish_measurement(m);

	sk_events_destroy(e);
}
