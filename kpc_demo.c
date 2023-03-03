#include <stdbool.h>
#include <locale.h>
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

// The maximum number of counters we could read from every class in one go.
// ARMV7: FIXED: 1, CONFIGURABLE: 4
// ARM32: FIXED: 2, CONFIGURABLE: 6
// ARM64: FIXED: 2, CONFIGURABLE: CORE_NCTRS - FIXED (6 or 8)
// x86: 32
#define KPC_MAX_COUNTERS 32

// Maximum number of kperf action ids.
#define KPERF_ACTION_MAX (32)

// Maximum number of kperf timer ids.
#define KPERF_TIMER_MAX (8)

// x86/arm config registers are 64-bit
typedef u64 kpc_config_t;

/// Print current CPU identification string to the buffer (same as snprintf),
/// such as "cpu_7_8_10b282dc_46". This string can be used to locate the PMC
/// database in /usr/share/kpep.
/// @return string's length, or negative value if error occurs.
/// @note This method does not requires root privileges.
/// @details sysctl get(hw.cputype), get(hw.cpusubtype),
///                 get(hw.cpufamily), get(machdep.cpu.model)
static int (*kpc_cpu_string)(char *buf, usize buf_size);

/// Get the version of KPC that's being run.
/// @return See `PMU version constants` above.
/// @details sysctl get(kpc.pmu_version)
static u32 (*kpc_pmu_version)(void);

/// Get running PMC classes.
/// @return See `class mask constants` above,
///         0 if error occurs or no class is set.
/// @details sysctl get(kpc.counting)
static u32 (*kpc_get_counting)(void);

/// Set PMC classes to enable counting.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.counting)
static int (*kpc_set_counting)(u32 classes);

/// Get running PMC classes for current thread.
/// @return See `class mask constants` above,
///         0 if error occurs or no class is set.
/// @details sysctl get(kpc.thread_counting)
static u32 (*kpc_get_thread_counting)(void);

/// Set PMC classes to enable counting for current thread.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.thread_counting)
static int (*kpc_set_thread_counting)(u32 classes);

/// Get how many config registers there are for a given mask.
/// For example: Intel may returns 1 for `KPC_CLASS_FIXED_MASK`,
///                        returns 4 for `KPC_CLASS_CONFIGURABLE_MASK`.
/// @param classes See `class mask constants` above.
/// @return 0 if error occurs or no class is set.
/// @note This method does not requires root privileges.
/// @details sysctl get(kpc.config_count)
static u32 (*kpc_get_config_count)(u32 classes);

/// Get config registers.
/// @param classes see `class mask constants` above.
/// @param config Config buffer to receive values, should not smaller than
///               kpc_get_config_count(classes) * sizeof(kpc_config_t).
/// @return 0 for success.
/// @details sysctl get(kpc.config_count), get(kpc.config)
static int (*kpc_get_config)(u32 classes, kpc_config_t *config);

/// Set config registers.
/// @param classes see `class mask constants` above.
/// @param config Config buffer, should not smaller than
///               kpc_get_config_count(classes) * sizeof(kpc_config_t).
/// @return 0 for success.
/// @details sysctl get(kpc.config_count), set(kpc.config)
static int (*kpc_set_config)(u32 classes, kpc_config_t *config);

/// Get how many counters there are for a given mask.
/// For example: Intel may returns 3 for `KPC_CLASS_FIXED_MASK`,
///                        returns 4 for `KPC_CLASS_CONFIGURABLE_MASK`.
/// @param classes See `class mask constants` above.
/// @note This method does not requires root privileges.
/// @details sysctl get(kpc.counter_count)
static u32 (*kpc_get_counter_count)(u32 classes);

/// Get counter accumulations.
/// If `all_cpus` is true, the buffer count should not smaller than
/// (cpu_count * counter_count). Otherwize, the buffer count should not smaller
/// than (counter_count).
/// @see kpc_get_counter_count(), kpc_cpu_count().
/// @param all_cpus true for all CPUs, false for current cpu.
/// @param classes See `class mask constants` above.
/// @param curcpu A pointer to receive current cpu id, can be NULL.
/// @param buf Buffer to receive counter's value.
/// @return 0 for success.
/// @details sysctl get(hw.ncpu), get(kpc.counter_count), get(kpc.counters)
static int (*kpc_get_cpu_counters)(bool all_cpus, u32 classes, int *curcpu,
				   u64 *buf);

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

/// Set number of actions, should be `KPERF_ACTION_MAX`.
/// @details sysctl set(kperf.action.count)
static int (*kperf_action_count_set)(u32 count);

/// Get number of actions.
/// @details sysctl get(kperf.action.count)
static int (*kperf_action_count_get)(u32 *count);

/// Set what to sample when a trigger fires an action, e.g.
/// `KPERF_SAMPLER_PMC_CPU`.
/// @details sysctl set(kperf.action.samplers)
static int (*kperf_action_samplers_set)(u32 actionid, u32 sample);

/// Get what to sample when a trigger fires an action.
/// @details sysctl get(kperf.action.samplers)
static int (*kperf_action_samplers_get)(u32 actionid, u32 *sample);

/// Apply a task filter to the action, -1 to disable filter.
/// @details sysctl set(kperf.action.filter_by_task)
static int (*kperf_action_filter_set_by_task)(u32 actionid, i32 port);

/// Apply a pid filter to the action, -1 to disable filter.
/// @details sysctl set(kperf.action.filter_by_pid)
static int (*kperf_action_filter_set_by_pid)(u32 actionid, i32 pid);

/// Set number of time triggers, should be `KPERF_TIMER_MAX`.
/// @details sysctl set(kperf.timer.count)
static int (*kperf_timer_count_set)(u32 count);

/// Get number of time triggers.
/// @details sysctl get(kperf.timer.count)
static int (*kperf_timer_count_get)(u32 *count);

/// Set timer number and period.
/// @details sysctl set(kperf.timer.period)
static int (*kperf_timer_period_set)(u32 actionid, u64 tick);

/// Get timer number and period.
/// @details sysctl get(kperf.timer.period)
static int (*kperf_timer_period_get)(u32 actionid, u64 *tick);

/// Set timer number and actionid.
/// @details sysctl set(kperf.timer.action)
static int (*kperf_timer_action_set)(u32 actionid, u32 timerid);

/// Get timer number and actionid.
/// @details sysctl get(kperf.timer.action)
static int (*kperf_timer_action_get)(u32 actionid, u32 *timerid);

/// Set which timer ID does PET (Profile Every Thread).
/// @details sysctl set(kperf.timer.pet_timer)
static int (*kperf_timer_pet_set)(u32 timerid);

/// Get which timer ID does PET (Profile Every Thread).
/// @details sysctl get(kperf.timer.pet_timer)
static int (*kperf_timer_pet_get)(u32 *timerid);

/// Enable or disable sampling.
/// @details sysctl set(kperf.sampling)
static int (*kperf_sample_set)(u32 enabled);

/// Get is currently sampling.
/// @details sysctl get(kperf.sampling)
static int (*kperf_sample_get)(u32 *enabled);

/// Reset kperf: stop sampling, kdebug, timers and actions.
/// @return 0 for success.
static int (*kperf_reset)(void);

/// Nanoseconds to CPU ticks.
static u64 (*kperf_ns_to_ticks)(u64 ns);

/// CPU ticks to nanoseconds.
static u64 (*kperf_ticks_to_ns)(u64 ticks);

/// CPU ticks frequency (mach_absolute_time).
static u64 (*kperf_tick_frequency)(void);

/// Get lightweight PET mode (not in kperf.framework).
static int kperf_lightweight_pet_get(u32 *enabled)
{
	if (!enabled)
		return -1;
	usize size = 4;
	return sysctlbyname("kperf.lightweight_pet", enabled, &size, NULL, 0);
}

/// Set lightweight PET mode (not in kperf.framework).
static int kperf_lightweight_pet_set(u32 enabled)
{
	return sysctlbyname("kperf.lightweight_pet", NULL, NULL, &enabled, 4);
}

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

/// KPEP database (size: 144/80 bytes on 64/32 bit OS)
typedef struct kpep_db {
	const char *name; ///< Database name, such as "haswell".
	const char *cpu_id; ///< Plist name, such as "cpu_7_8_10b282dc".
	const char
		*marketing_name; ///< Marketing name, such as "Intel Haswell".
	void *plist_data; ///< Plist data (CFDataRef), currently NULL.
	void *event_map; ///< All events (CFDict<CFSTR(event_name), kpep_event
			 ///< *>).
	kpep_event *event_arr; ///< Event struct buffer (sizeof(kpep_event) *
			       ///< events_count).
	kpep_event **
		fixed_event_arr; ///< Fixed counter events (sizeof(kpep_event *)
				 ///< * fixed_counter_count)
	void *alias_map; ///< All aliases (CFDict<CFSTR(event_name), kpep_event
			 ///< *>).
	usize reserved_1;
	usize reserved_2;
	usize reserved_3;
	usize event_count; ///< All events count.
	usize alias_count;
	usize fixed_counter_count;
	usize config_counter_count;
	usize power_counter_count;
	u32 archtecture; ///< see `KPEP CPU archtecture constants` above.
	u32 fixed_counter_bits;
	u32 config_counter_bits;
	u32 power_counter_bits;
} kpep_db;

/// KPEP config (size: 80/44 bytes on 64/32 bit OS)
typedef struct kpep_config {
	kpep_db *db;
	kpep_event *
		*events; ///< (sizeof(kpep_event *) * counter_count), init NULL
	usize *ev_map; ///< (sizeof(usize *) * counter_count), init 0
	usize *ev_idx; ///< (sizeof(usize *) * counter_count), init -1
	u32 *flags; ///< (sizeof(u32 *) * counter_count), init 0
	u64 *kpc_periods; ///< (sizeof(u64 *) * counter_count), init 0
	usize event_count; /// kpep_config_events_count()
	usize counter_count;
	u32 classes; ///< See `class mask constants` above.
	u32 config_counter;
	u32 power_counter;
	u32 reserved;
} kpep_config;

/// Error code for kpep_config_xxx() and kpep_db_xxx() functions.
typedef enum {
	KPEP_CONFIG_ERROR_NONE = 0,
	KPEP_CONFIG_ERROR_INVALID_ARGUMENT = 1,
	KPEP_CONFIG_ERROR_OUT_OF_MEMORY = 2,
	KPEP_CONFIG_ERROR_IO = 3,
	KPEP_CONFIG_ERROR_BUFFER_TOO_SMALL = 4,
	KPEP_CONFIG_ERROR_CUR_SYSTEM_UNKNOWN = 5,
	KPEP_CONFIG_ERROR_DB_PATH_INVALID = 6,
	KPEP_CONFIG_ERROR_DB_NOT_FOUND = 7,
	KPEP_CONFIG_ERROR_DB_ARCH_UNSUPPORTED = 8,
	KPEP_CONFIG_ERROR_DB_VERSION_UNSUPPORTED = 9,
	KPEP_CONFIG_ERROR_DB_CORRUPT = 10,
	KPEP_CONFIG_ERROR_EVENT_NOT_FOUND = 11,
	KPEP_CONFIG_ERROR_CONFLICTING_EVENTS = 12,
	KPEP_CONFIG_ERROR_COUNTERS_NOT_FORCED = 13,
	KPEP_CONFIG_ERROR_EVENT_UNAVAILABLE = 14,
	KPEP_CONFIG_ERROR_ERRNO = 15,
	KPEP_CONFIG_ERROR_MAX
} kpep_config_error_code;

/// Error description for kpep_config_error_code.
static const char *kpep_config_error_names[KPEP_CONFIG_ERROR_MAX] = {
	"none",
	"invalid argument",
	"out of memory",
	"I/O",
	"buffer too small",
	"current system unknown",
	"database path invalid",
	"database not found",
	"database architecture unsupported",
	"database version unsupported",
	"database corrupt",
	"event not found",
	"conflicting events",
	"all counters must be forced",
	"event unavailable",
	"check errno"
};

/// Error description.
static const char *kpep_config_error_desc(int code)
{
	if (0 <= code && code < KPEP_CONFIG_ERROR_MAX) {
		return kpep_config_error_names[code];
	}
	return "unknown error";
}

/// Create a config.
/// @param db A kpep db, see kpep_db_create()
/// @param cfg_ptr A pointer to receive the new config.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_create)(kpep_db *db, kpep_config **cfg_ptr);

/// Free the config.
static void (*kpep_config_free)(kpep_config *cfg);

/// Add an event to config.
/// @param cfg The config.
/// @param ev_ptr A event pointer.
/// @param flag 0: all, 1: user space only
/// @param err Error bitmap pointer, can be NULL.
///            If return value is `CONFLICTING_EVENTS`, this bitmap contains
///            the conflicted event indices, e.g. "1 << 2" means index 2.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_add_event)(kpep_config *cfg, kpep_event **ev_ptr,
				    u32 flag, u32 *err);

/// Remove event at index.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_remove_event)(kpep_config *cfg, usize idx);

/// Force all counters.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_force_counters)(kpep_config *cfg);

/// Get events count.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_events_count)(kpep_config *cfg, usize *count_ptr);

/// Get all event pointers.
/// @param buf A buffer to receive event pointers.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_events_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_events)(kpep_config *cfg, kpep_event **buf,
				 usize buf_size);

/// Get kpc register configs.
/// @param buf A buffer to receive kpc register configs.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_kpc_count() * sizeof(kpc_config_t).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc)(kpep_config *cfg, kpc_config_t *buf,
			      usize buf_size);

/// Get kpc register config count.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc_count)(kpep_config *cfg, usize *count_ptr);

/// Get kpc classes.
/// @param classes See `class mask constants` above.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc_classes)(kpep_config *cfg, u32 *classes_ptr);

/// Get the index mapping from event to counter.
/// @param buf A buffer to receive indexes.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_events_count() * sizeof(kpc_config_t).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_config_kpc_map)(kpep_config *cfg, usize *buf, usize buf_size);

/// Open a kpep database file in "/usr/share/kpep/" or "/usr/local/share/kpep/".
/// @param name File name, for example "haswell", "cpu_100000c_1_92fb37c8".
///             Pass NULL for current CPU.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_create)(const char *name, kpep_db **db_ptr);

/// Free the kpep database.
static void (*kpep_db_free)(kpep_db *db);

/// Get the database's name.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_name)(kpep_db *db, const char **name);

/// Get the event alias count.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_aliases_count)(kpep_db *db, usize *count);

/// Get all alias.
/// @param buf A buffer to receive all alias strings.
/// @param buf_size The buffer's size in bytes,
///        should not smaller than kpep_db_aliases_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_aliases)(kpep_db *db, const char **buf, usize buf_size);

/// Get counters count for given classes.
/// @param classes 1: Fixed, 2: Configurable.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_counters_count)(kpep_db *db, u8 classes, usize *count);

/// Get all event count.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_events_count)(kpep_db *db, usize *count);

/// Get all events.
/// @param buf A buffer to receive all event pointers.
/// @param buf_size The buffer's size in bytes,
///        should not smaller than kpep_db_events_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_events)(kpep_db *db, kpep_event **buf, usize buf_size);

/// Get one event by name.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_db_event)(kpep_db *db, const char *name, kpep_event **ev_ptr);

/// Get event's name.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_event_name)(kpep_event *ev, const char **name_ptr);

/// Get event's alias.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_event_alias)(kpep_event *ev, const char **alias_ptr);

/// Get event's description.
/// @return kpep_config_error_code, 0 for success.
static int (*kpep_event_description)(kpep_event *ev, const char **str_ptr);

// -----------------------------------------------------------------------------
// load kperf/kperfdata dynamic library
// -----------------------------------------------------------------------------

typedef struct {
	const char *name;
	void **impl;
} lib_symbol;

#define lib_nelems(x) (sizeof(x) / sizeof((x)[0]))
#define lib_symbol_def(name)                                                   \
	{                                                                      \
#name, (void **)&name                                          \
	}

static const lib_symbol lib_symbols_kperf[] = {
	lib_symbol_def(kpc_pmu_version),
	lib_symbol_def(kpc_cpu_string),
	lib_symbol_def(kpc_set_counting),
	lib_symbol_def(kpc_get_counting),
	lib_symbol_def(kpc_set_thread_counting),
	lib_symbol_def(kpc_get_thread_counting),
	lib_symbol_def(kpc_get_config_count),
	lib_symbol_def(kpc_get_counter_count),
	lib_symbol_def(kpc_set_config),
	lib_symbol_def(kpc_get_config),
	lib_symbol_def(kpc_get_cpu_counters),
	lib_symbol_def(kpc_get_thread_counters),
	lib_symbol_def(kpc_force_all_ctrs_set),
	lib_symbol_def(kpc_force_all_ctrs_get),
	lib_symbol_def(kperf_action_count_set),
	lib_symbol_def(kperf_action_count_get),
	lib_symbol_def(kperf_action_samplers_set),
	lib_symbol_def(kperf_action_samplers_get),
	lib_symbol_def(kperf_action_filter_set_by_task),
	lib_symbol_def(kperf_action_filter_set_by_pid),
	lib_symbol_def(kperf_timer_count_set),
	lib_symbol_def(kperf_timer_count_get),
	lib_symbol_def(kperf_timer_period_set),
	lib_symbol_def(kperf_timer_period_get),
	lib_symbol_def(kperf_timer_action_set),
	lib_symbol_def(kperf_timer_action_get),
	lib_symbol_def(kperf_sample_set),
	lib_symbol_def(kperf_sample_get),
	lib_symbol_def(kperf_reset),
	lib_symbol_def(kperf_timer_pet_set),
	lib_symbol_def(kperf_timer_pet_get),
	lib_symbol_def(kperf_ns_to_ticks),
	lib_symbol_def(kperf_ticks_to_ns),
	lib_symbol_def(kperf_tick_frequency),
};

static const lib_symbol lib_symbols_kperfdata[] = {
	lib_symbol_def(kpep_config_create),
	lib_symbol_def(kpep_config_free),
	lib_symbol_def(kpep_config_add_event),
	lib_symbol_def(kpep_config_remove_event),
	lib_symbol_def(kpep_config_force_counters),
	lib_symbol_def(kpep_config_events_count),
	lib_symbol_def(kpep_config_events),
	lib_symbol_def(kpep_config_kpc),
	lib_symbol_def(kpep_config_kpc_count),
	lib_symbol_def(kpep_config_kpc_classes),
	lib_symbol_def(kpep_config_kpc_map),
	lib_symbol_def(kpep_db_create),
	lib_symbol_def(kpep_db_free),
	lib_symbol_def(kpep_db_name),
	lib_symbol_def(kpep_db_aliases_count),
	lib_symbol_def(kpep_db_aliases),
	lib_symbol_def(kpep_db_counters_count),
	lib_symbol_def(kpep_db_events_count),
	lib_symbol_def(kpep_db_events),
	lib_symbol_def(kpep_db_event),
	lib_symbol_def(kpep_event_name),
	lib_symbol_def(kpep_event_alias),
	lib_symbol_def(kpep_event_description),
};

#define lib_path_kperf "/System/Library/PrivateFrameworks/kperf.framework/kperf"
#define lib_path_kperfdata                                                     \
	"/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"

static bool lib_inited = false;
static bool lib_has_err = false;
static char lib_err_msg[256];

static void *lib_handle_kperf = NULL;
static void *lib_handle_kperfdata = NULL;

static void lib_deinit(void)
{
	lib_inited = false;
	lib_has_err = false;
	if (lib_handle_kperf)
		dlclose(lib_handle_kperf);
	if (lib_handle_kperfdata)
		dlclose(lib_handle_kperfdata);
	lib_handle_kperf = NULL;
	lib_handle_kperfdata = NULL;
	for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++) {
		const lib_symbol *symbol = &lib_symbols_kperf[i];
		*symbol->impl = NULL;
	}
	for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++) {
		const lib_symbol *symbol = &lib_symbols_kperfdata[i];
		*symbol->impl = NULL;
	}
}

static bool lib_init(void)
{
#define return_err()                                                           \
	do {                                                                   \
		lib_deinit();                                                  \
		lib_inited = true;                                             \
		lib_has_err = true;                                            \
		return false;                                                  \
	} while (false)

	if (lib_inited)
		return !lib_has_err;

	// load dynamic library
	lib_handle_kperf = dlopen(lib_path_kperf, RTLD_LAZY);
	if (!lib_handle_kperf) {
		snprintf(lib_err_msg, sizeof(lib_err_msg),
			 "Failed to load kperf.framework, message: %s.",
			 dlerror());
		return_err();
	}
	lib_handle_kperfdata = dlopen(lib_path_kperfdata, RTLD_LAZY);
	if (!lib_handle_kperfdata) {
		snprintf(lib_err_msg, sizeof(lib_err_msg),
			 "Failed to load kperfdata.framework, message: %s.",
			 dlerror());
		return_err();
	}

	// load symbol address from dynamic library
	for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++) {
		const lib_symbol *symbol = &lib_symbols_kperf[i];
		*symbol->impl = dlsym(lib_handle_kperf, symbol->name);
		if (!*symbol->impl) {
			snprintf(lib_err_msg, sizeof(lib_err_msg),
				 "Failed to load kperf function: %s.",
				 symbol->name);
			return_err();
		}
	}
	for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++) {
		const lib_symbol *symbol = &lib_symbols_kperfdata[i];
		*symbol->impl = dlsym(lib_handle_kperfdata, symbol->name);
		if (!*symbol->impl) {
			snprintf(lib_err_msg, sizeof(lib_err_msg),
				 "Failed to load kperfdata function: %s.",
				 symbol->name);
			return_err();
		}
	}

	lib_inited = true;
	lib_has_err = false;
	return true;

#undef return_err
}

// -----------------------------------------------------------------------------
// kdebug private structs
// https://github.com/apple/darwin-xnu/blob/main/bsd/sys_private/kdebug_private.h
// -----------------------------------------------------------------------------

/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__arm64__)
typedef uint64_t kd_buf_argtype;
#else
typedef uintptr_t kd_buf_argtype;
#endif

typedef struct {
	uint64_t timestamp;
	kd_buf_argtype arg1;
	kd_buf_argtype arg2;
	kd_buf_argtype arg3;
	kd_buf_argtype arg4;
	kd_buf_argtype arg5; /* the thread ID */
	uint32_t debugid; /* see <sys/kdebug.h> */

/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__LP64__) || defined(__arm64__)
	uint32_t cpuid; /* cpu index, from 0 */
	kd_buf_argtype unused;
#endif
} kd_buf;

/* bits for the type field of kd_regtype */
#define KDBG_CLASSTYPE 0x10000
#define KDBG_SUBCLSTYPE 0x20000
#define KDBG_RANGETYPE 0x40000
#define KDBG_TYPENONE 0x80000
#define KDBG_CKTYPES 0xF0000

/* only trace at most 4 types of events, at the code granularity */
#define KDBG_VALCHECK 0x00200000U

typedef struct {
	unsigned int type;
	unsigned int value1;
	unsigned int value2;
	unsigned int value3;
	unsigned int value4;
} kd_regtype;

typedef struct {
	/* number of events that can fit in the buffers */
	int nkdbufs;
	/* set if trace is disabled */
	int nolog;
	/* kd_ctrl_page.flags */
	unsigned int flags;
	/* number of threads in thread map */
	int nkdthreads;
	/* the owning pid */
	int bufid;
} kbufinfo_t;

// -----------------------------------------------------------------------------
// kdebug utils
// -----------------------------------------------------------------------------

/// Clean up trace buffers and reset ktrace/kdebug/kperf.
/// @return 0 on success.
static int kdebug_reset(void)
{
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE };
	return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

/// Disable and reinitialize the trace buffers.
/// @return 0 on success.
static int kdebug_reinit(void)
{
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETUP };
	return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

/// Set debug filter.
static int kdebug_setreg(kd_regtype *kdr)
{
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETREG };
	usize size = sizeof(kd_regtype);
	return sysctl(mib, 3, kdr, &size, NULL, 0);
}

/// Set maximum number of trace entries (kd_buf).
/// Only allow allocation up to half the available memory (sane_size).
/// @return 0 on success.
static int kdebug_trace_setbuf(int nbufs)
{
	int mib[4] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, nbufs };
	return sysctl(mib, 4, NULL, NULL, NULL, 0);
}

/// Enable or disable kdebug trace.
/// Trace buffer must already be initialized.
/// @return 0 on success.
static int kdebug_trace_enable(bool enable)
{
	int mib[4] = { CTL_KERN, KERN_KDEBUG, KERN_KDENABLE, enable };
	return sysctl(mib, 4, NULL, 0, NULL, 0);
}

/// Retrieve trace buffer information from kernel.
/// @return 0 on success.
static int kdebug_get_bufinfo(kbufinfo_t *info)
{
	if (!info)
		return -1;
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF };
	size_t needed = sizeof(kbufinfo_t);
	return sysctl(mib, 3, info, &needed, NULL, 0);
}

/// Retrieve trace buffers from kernel.
/// @param buf Memory to receive buffer data, array of `kd_buf`.
/// @param len Length of `buf` in bytes.
/// @param count Number of trace entries (kd_buf) obtained.
/// @return 0 on success.
static int kdebug_trace_read(void *buf, usize len, usize *count)
{
	if (count)
		*count = 0;
	if (!buf || !len)
		return -1;

	// Note: the input and output units are not the same.
	// input: bytes
	// output: number of kd_buf
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDREADTR };
	int ret = sysctl(mib, 3, buf, &len, NULL, 0);
	if (ret != 0)
		return ret;
	*count = len;
	return 0;
}

/// Block until there are new buffers filled or `timeout_ms` have passed.
/// @param timeout_ms timeout milliseconds, 0 means wait forever.
/// @param suc set true if new buffers filled.
/// @return 0 on success.
static int kdebug_wait(usize timeout_ms, bool *suc)
{
	if (timeout_ms == 0)
		return -1;
	int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDBUFWAIT };
	usize val = timeout_ms;
	int ret = sysctl(mib, 3, NULL, &val, NULL, 0);
	if (suc)
		*suc = !!val;
	return ret;
}

// -----------------------------------------------------------------------------
// Demo
// -----------------------------------------------------------------------------

static void profile_func(void)
{
	for (u32 i = 0; i < 100000; i++) {
		u32 r = arc4random();
		if (r % 2)
			arc4random();
	}
}

struct events {
	const char **human_readable_names;
	const char **internal_names;
	usize count;
};
typedef void *events;

events events_create()
{
	struct events *e = calloc(1, sizeof(struct events));
	*e = (struct events){
		.human_readable_names = calloc(KPC_MAX_COUNTERS, sizeof(const char *)),
		.internal_names = calloc(KPC_MAX_COUNTERS, sizeof(const char *)),
		.count = 0,
	};
	return e;
}

void events_push(
		events events,
		const char *human_readable_name,
		const char *internal_name)
{
	struct events *e = events;
	e->human_readable_names[e->count] = human_readable_name;
	e->internal_names[e->count] = internal_name;
	e->count++;
}

void events_destroy(events events)
{
	struct events *e = events;
	free(e->human_readable_names);
	free(e->internal_names);
	free(e);
}

struct in_progress_measurement_internal {
	struct events *events;
	u32 classes;
	usize counter_map[KPC_MAX_COUNTERS];
	u64 regs[KPC_MAX_COUNTERS];
	u64 counters[KPC_MAX_COUNTERS];
};

typedef void *in_progress_measurement;

in_progress_measurement start_measurement(events events)
{
	struct in_progress_measurement_internal *m =
		calloc(1, sizeof(struct in_progress_measurement_internal));
	*m = (struct in_progress_measurement_internal){
		.events = events,
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
			const char *human_readable_name = m->events->human_readable_names[i];
			printf("Cannot find event for %s: “%s”.\n",
				human_readable_name,
				internal_name);
			exit(1);
		}

		kpep_config_add_event(kpep_config, &event, 0, NULL);
	}

	kpep_config_kpc_classes(kpep_config, &m->classes);
	kpep_config_kpc_map(kpep_config, m->counter_map, sizeof(m->counter_map));
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

void finish_measurement(in_progress_measurement m)
{
	struct in_progress_measurement_internal *mi = m;

	u64 counters_after[KPC_MAX_COUNTERS] = { 0 };

	// Don’t put any library code above these kpc calls!
	// We don’t want to execute anything until timing has stopped
	kpc_get_thread_counters(0, KPC_MAX_COUNTERS, counters_after);
	kpc_set_counting(0);
	kpc_force_all_ctrs_set(0);

	setlocale(LC_NUMERIC, "");
	printf("counters value:\n");
	for (usize i = 0; i < mi->events->count; i++) {
		const char *name = mi->events->human_readable_names[i];
		usize idx = mi->counter_map[i];
		u64 diff = counters_after[idx] - mi->counters[idx];
		printf("%40s: %15'llu\n", name, diff);
	}

	free(m);
}

int main(int argc, const char *argv[])
{
	lib_init();

	if (kpc_force_all_ctrs_get(NULL) != 0) {
		printf("Permission denied, xnu/kpc requires root privileges.\n");
		return 1;
	}

	events e = events_create();
	events_push(e, "cycles", "FIXED_CYCLES");
	events_push(e, "instructions", "FIXED_INSTRUCTIONS");
	events_push(e, "branches", "INST_BRANCH");
	events_push(e, "branch misses", "BRANCH_MISPRED_NONSPEC");
	events_push(e, "subroutine calls", "INST_BRANCH_CALL");

	in_progress_measurement m = start_measurement(e);
	profile_func();
	finish_measurement(m);

	events_destroy(e);
}
