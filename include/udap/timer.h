#ifndef UDAP_TIMER_H
#define UDAP_TIMER_H
#include <udap/common.h>
#include <udap/threadpool.h>
#ifdef __cplusplus
extern "C" {
#endif

/** called with userptr, original timeout, left */
typedef void (*udap_timer_handler_func)(void *, uint64_t, uint64_t);

struct udap_timeout_job
{
  uint64_t timeout;
  void *user;
  udap_timer_handler_func handler;
};

struct udap_timer_context;

struct udap_timer_context *
udap_init_timer();

uint32_t
udap_timer_call_later(struct udap_timer_context *t,
                       struct udap_timeout_job job);

void
udap_timer_cancel_job(struct udap_timer_context *t, uint32_t id);

void
udap_timer_remove_job(struct udap_timer_context *t, uint32_t id);

// cancel all
void
udap_timer_stop(struct udap_timer_context *t);

// blocking run timer and send events to thread pool
void
udap_timer_run(struct udap_timer_context *t, struct udap_threadpool *pool);

/// single threaded run timer, tick all timers
void
udap_timer_tick_all(struct udap_timer_context *t,
                     struct udap_threadpool *pool);

void
udap_free_timer(struct udap_timer_context **t);

#ifdef __cplusplus
}
#endif
#endif
