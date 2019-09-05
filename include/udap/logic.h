#ifndef UDAP_LOGIC_H
#define UDAP_LOGIC_H
#include <udap/mem.h>
#include <udap/threadpool.h>
#include <udap/timer.h>
#ifdef __cplusplus
extern "C" {
#endif

struct udap_logic;

struct udap_logic*
udap_init_logic();

/// single threaded mode logic event loop
struct udap_logic*
udap_init_single_process_logic(struct udap_threadpool* tp);

/// single threaded tick
void
udap_logic_tick(struct udap_logic* logic);

void
udap_free_logic(struct udap_logic** logic);

void
udap_logic_queue_job(struct udap_logic* logic, struct udap_thread_job job);

uint32_t
udap_logic_call_later(struct udap_logic* logic, struct udap_timeout_job job);
void
udap_logic_cancel_call(struct udap_logic* logic, uint32_t id);

void
udap_logic_remove_call(struct udap_logic* logic, uint32_t id);

void
udap_logic_stop(struct udap_logic* logic);

void
udap_logic_mainloop(struct udap_logic* logic);

#ifdef __cplusplus
}
#endif
#endif
