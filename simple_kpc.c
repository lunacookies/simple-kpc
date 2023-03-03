#include "simple_kpc.h"

#include <assert.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h> // for dlopen() and dlsym()
#include <sys/sysctl.h> // for sysctl()

typedef float f32;
typedef double f64;
typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef size_t usize;

#define ARRAY_LENGTH(x) (sizeof(x) / sizeof((x)[0]))

// The maximum number of counters we could read from every class in one go.
// ARMV7: FIXED: 1, CONFIGURABLE: 4
// ARM32: FIXED: 2, CONFIGURABLE: 6
// ARM64: FIXED: 2, CONFIGURABLE: CORE_NCTRS - FIXED (6 or 8)
// x86: 32
#define KPC_MAX_COUNTERS 32

/// Set PMC classes to enable counting.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.counting)
static int (*kpc_set_counting)(u32 classes);

/// Set PMC classes to enable counting for current thread.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.thread_counting)
static int (*kpc_set_thread_counting)(u32 classes);

/// Set config registers.
/// @param classes see `class mask constants` above.
/// @param config Config buffer, should not smaller than
///               kpc_get_config_count(classes) * sizeof(u64).
/// @return 0 for success.
/// @details sysctl get(kpc.config_count), set(kpc.config)
static int (*kpc_set_config)(u32 classes, u64 *config);

/// Get counter accumulations for current thread.
/// @param tid Thread id, should be 0.
/// @param buf_count The number of buf's elements (not bytes),
///                  should not smaller than kpc_get_counter_count().
/// @param buf Buffer to receive counter's value.
/// @return 0 for success.
/// @details sysctl get(kpc.thread_counters)
static int (*kpc_get_thread_counters)(u32 tid, u32 buf_count, u64 *buf);

/// Acquire/release the counters used by the Power Manager.
/// @param val 1:acquire, 0:release
/// @return 0 for success.
/// @details sysctl set(kpc.force_all_ctrs)
static int (*kpc_force_all_ctrs_set)(int val);

/// Get the state of all_ctrs.
/// @return 0 for success.
/// @details sysctl get(kpc.force_all_ctrs)
static int (*kpc_force_all_ctrs_get)(int *val_out);

// -----------------------------------------------------------------------------
// <kperfdata.framework> header (reverse engineered)
// This framework provides some functions to access the local CPU database.
// These functions do not require root privileges.
// -----------------------------------------------------------------------------

/// KPEP event (size: 48/28 bytes on 64/32 bit OS)
typedef struct kpep_event {
	const char
		*name; ///< Unique name of a event, such as "INST_RETIRED.ANY".
	const char *description; ///< Description for this event.
	const char *errata; ///< Errata, currently NULL.
	const char *alias; ///< Alias name, such as "Instructions", "Cycles".
	const char *fallback; ///< Fallback event name for fixed counter.
	u32 mask;
	u8 number;
	u8 umask;
	u8 reserved;
	u8 is_fixed;
} kpep_event;

/// Create a config.
/// @param db A kpep db, see kpep_db_create()
/// @param cfg_ptr A pointer to receive the new config.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_create)(void *db, void **cfg_ptr);

/// Free the config.
static void (*kpep_config_free)(void *cfg);

/// Add an event to config.
/// @param cfg The config.
/// @param ev_ptr A event pointer.
/// @param flag 0: all, 1: user space only
/// @param err Error bitmap pointer, can be NULL.
///            If return value is `CONFLICTING_EVENTS`, this bitmap contains
///            the conflicted event indices, e.g. "1 << 2" means index 2.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_add_event)(void *cfg, void **ev_ptr, u32 flag,
				    u32 *err);

/// Force all counters.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_force_counters)(void *cfg);

/// Get kpc register configs.
/// @param buf A buffer to receive kpc register configs.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_kpc_count() * sizeof(u64).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc)(void *cfg, u64 *buf, usize buf_size);

/// Get kpc classes.
/// @param classes See `class mask constants` above.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc_classes)(void *cfg, u32 *classes_ptr);

/// Get the index mapping from event to counter.
/// @param buf A buffer to receive indexes.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_events_count() * sizeof(u64).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc_map)(void *cfg, usize *buf, usize buf_size);

/// Open a kpep database file in "/usr/share/kpep/" or "/usr/local/share/kpep/".
/// @param name File name, for example "haswell", "cpu_100000c_1_92fb37c8".
///             Pass NULL for current CPU.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_create)(const char *name, void **db_ptr);

/// Free the kpep database.
static void (*kpep_db_free)(void *db);

/// Get all event count.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_events_count)(void *db, usize *count);

/// Get all events.
/// @param buf A buffer to receive all event pointers.
/// @param buf_size The buffer's size in bytes,
///        should not smaller than kpep_db_events_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_events)(void *db, void **buf, usize buf_size);

/// Get one event by name.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_event)(void *db, const char *name, void **ev_ptr);

typedef struct {
	const char *name;
	void **impl;
} symbol;

#define SYMBOL(n) { .name = #n, .impl = (void **)&n }

static const symbol KPERF_SYMBOLS[] = {
	SYMBOL(kpc_set_counting),
	SYMBOL(kpc_set_thread_counting),
	SYMBOL(kpc_set_config),
	SYMBOL(kpc_get_thread_counters),
	SYMBOL(kpc_force_all_ctrs_set),
	SYMBOL(kpc_force_all_ctrs_get),
};

static const symbol KPERFDATA_SYMBOLS[] = {
	SYMBOL(kpep_config_create),
	SYMBOL(kpep_config_free),
	SYMBOL(kpep_config_add_event),
	SYMBOL(kpep_config_force_counters),
	SYMBOL(kpep_config_kpc),
	SYMBOL(kpep_config_kpc_classes),
	SYMBOL(kpep_config_kpc_map),
	SYMBOL(kpep_db_create),
	SYMBOL(kpep_db_free),
	SYMBOL(kpep_db_events_count),
	SYMBOL(kpep_db_events),
	SYMBOL(kpep_db_event),
};

#define KPERF_PATH "/System/Library/PrivateFrameworks/kperf.framework/kperf"
#define KPERFDATA_PATH                                                         \
	"/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"

static bool initialized = false;

void sk_init(void)
{
	if (initialized)
		return;

	void *kperf = dlopen(KPERF_PATH, RTLD_LAZY);
	if (!kperf) {
		fprintf(stderr, "simple_kpc: failed to load kperf.framework, message: %s\n",
			dlerror());
		exit(1);
	}

	void *kperfdata = dlopen(KPERFDATA_PATH, RTLD_LAZY);
	if (!kperfdata) {
		fprintf(stderr,
			"simple_kpc: failed to load kperfdata.framework, message: %s\n",
			dlerror());
		exit(1);
	}

	for (usize i = 0; i < ARRAY_LENGTH(KPERF_SYMBOLS); i++) {
		const symbol *symbol = &KPERF_SYMBOLS[i];
		*symbol->impl = dlsym(kperf, symbol->name);
		if (!*symbol->impl) {
			fprintf(stderr, "simple_kpc: failed to load kperf function %s\n",
				symbol->name);
			exit(1);
		}
	}

	for (usize i = 0; i < ARRAY_LENGTH(KPERFDATA_SYMBOLS); i++) {
		const symbol *symbol = &KPERFDATA_SYMBOLS[i];
		void *p = dlsym(kperfdata, symbol->name);
		if (!p) {
			fprintf(stderr,
				"simple_kpc: failed to load kperfdata function %s\n",
				symbol->name);
			exit(1);
		}
		*symbol->impl = p;
	}

	if (kpc_force_all_ctrs_get(NULL) != 0) {
		fprintf(stderr, "simple_kpc: permission denied, xnu/kpc requires root privileges\n");
		exit(1);
	}

	initialized = true;
}

static void profile_func(void)
{
	for (u32 i = 0; i < 100000; i++) {
		u32 r = arc4random();
		if (r % 2)
			arc4random();
	}
}

struct sk_events {
	const char **human_readable_names;
	const char **internal_names;
	usize count;
};

sk_events *sk_events_create(void)
{
	sk_events *e = calloc(1, sizeof(sk_events));
	*e = (sk_events){
		.human_readable_names =
			calloc(KPC_MAX_COUNTERS, sizeof(const char *)),
		.internal_names =
			calloc(KPC_MAX_COUNTERS, sizeof(const char *)),
		.count = 0,
	};
	return e;
}

void sk_events_push(sk_events *e, const char *human_readable_name,
		    const char *internal_name)
{
	e->human_readable_names[e->count] = human_readable_name;
	e->internal_names[e->count] = internal_name;
	e->count++;
}

void sk_events_destroy(sk_events *e)
{
	free(e->human_readable_names);
	free(e->internal_names);
	free(e);
}

struct sk_in_progress_measurement {
	sk_events *events;
	u32 classes;
	usize counter_map[KPC_MAX_COUNTERS];
	u64 regs[KPC_MAX_COUNTERS];
	u64 counters[KPC_MAX_COUNTERS];
};

sk_in_progress_measurement *sk_start_measurement(sk_events *e)
{
	assert(initialized);

	sk_in_progress_measurement *m =
		calloc(1, sizeof(sk_in_progress_measurement));
	*m = (sk_in_progress_measurement){
		.events = e,
		.classes = 0,
		.counter_map = { 0 },
		.counters = { 0 },
	};

	void *kpep_db = NULL;
	kpep_db_create(NULL, &kpep_db);

	void *kpep_config = NULL;
	kpep_config_create(kpep_db, &kpep_config);
	kpep_config_force_counters(kpep_config);

	for (usize i = 0; i < m->events->count; i++) {
		const char *internal_name = m->events->internal_names[i];
		void *event = NULL;
		kpep_db_event(kpep_db, internal_name, &event);

		if (event == NULL) {
			const char *human_readable_name =
				m->events->human_readable_names[i];
			printf("Cannot find event for %s: “%s”.\n",
			       human_readable_name, internal_name);
			exit(1);
		}

		kpep_config_add_event(kpep_config, &event, 0, NULL);
	}

	kpep_config_kpc_classes(kpep_config, &m->classes);
	kpep_config_kpc_map(kpep_config, m->counter_map,
			    sizeof(m->counter_map));
	kpep_config_kpc(kpep_config, m->regs, sizeof(m->regs));

	kpep_config_free(kpep_config);
	kpep_db_free(kpep_db);

	kpc_force_all_ctrs_set(1);
	kpc_set_config(m->classes, m->regs);

	// Don’t put any library code below these kpc calls!
	kpc_set_counting(m->classes);
	kpc_set_thread_counting(m->classes);
	kpc_get_thread_counters(0, KPC_MAX_COUNTERS, m->counters);
	return m;
}

void sk_finish_measurement(sk_in_progress_measurement *m)
{
	u64 counters_after[KPC_MAX_COUNTERS] = { 0 };

	// Don’t put any library code above these kpc calls!
	// We don’t want to execute anything until timing has stopped
	kpc_get_thread_counters(0, KPC_MAX_COUNTERS, counters_after);
	kpc_set_counting(0);
	kpc_force_all_ctrs_set(0);

	printf("\033[1m=== simple-kpc report ===\033[m\n\n");
	setlocale(LC_NUMERIC, "");
	for (usize i = 0; i < m->events->count; i++) {
		const char *name = m->events->human_readable_names[i];
		usize idx = m->counter_map[i];
		u64 diff = counters_after[idx] - m->counters[idx];
		printf("\033[32m%16'llu \033[95m%s\033[m\n", diff, name);
	}

	free(m);
}

int main(int argc, const char *argv[])
{
	sk_init();

	sk_events *e = sk_events_create();
	sk_events_push(e, "cycles", "FIXED_CYCLES");
	sk_events_push(e, "instructions", "FIXED_INSTRUCTIONS");
	sk_events_push(e, "branches", "INST_BRANCH");
	sk_events_push(e, "branch misses", "BRANCH_MISPRED_NONSPEC");
	sk_events_push(e, "subroutine calls", "INST_BRANCH_CALL");

	sk_in_progress_measurement *m = sk_start_measurement(e);
	profile_func();
	sk_finish_measurement(m);

	sk_events_destroy(e);
}
