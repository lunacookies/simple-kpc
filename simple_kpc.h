typedef struct {
	void *p;
} sk_events;

sk_events sk_events_create(void);
void sk_events_push(sk_events events, const char *human_readable_name,
const char *internal_name);
void sk_events_destroy(sk_events events);

typedef struct {
	void *p;
} sk_in_progress_measurement;

sk_in_progress_measurement sk_start_measurement(sk_events events);
void sk_finish_measurement(sk_in_progress_measurement in_progress_measurement);
