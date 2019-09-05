#include <udap/logic.h>
#include <udap/mem.h>
#include "logger.hpp"

struct udap_logic
{
  struct udap_threadpool* thread;
  struct udap_timer_context* timer;
};

extern "C" {

struct udap_logic*
udap_init_logic()
{
  udap_logic* logic = new udap_logic;
  if(logic)
  {
    logic->thread = udap_init_threadpool(1, "udap-logic");
    logic->timer  = udap_init_timer();
  }
  return logic;
};

struct udap_logic*
udap_init_single_process_logic(struct udap_threadpool* tp)
{
  udap_logic* logic = new udap_logic;
  if(logic)
  {
    logic->thread = tp;
    logic->timer  = udap_init_timer();
  }
  return logic;
}

void
udap_logic_tick(struct udap_logic* logic)
{
  udap_timer_tick_all(logic->timer, logic->thread);
}

void
udap_free_logic(struct udap_logic** logic)
{
  if(*logic)
  {
    // udap_free_timer(&(*logic)->timer);
    delete *logic;
  }
  *logic = nullptr;
}

void
udap_logic_stop(struct udap_logic* logic)
{
  udap::Debug("logic thread stop");
  if(logic->thread)
  {
    udap_threadpool_stop(logic->thread);
    udap_threadpool_join(logic->thread);
  }
  udap_free_threadpool(&logic->thread);

  udap::Debug("logic timer stop");
  if(logic->timer)
    udap_timer_stop(logic->timer);
}

void
udap_logic_mainloop(struct udap_logic* logic)
{
  udap_timer_run(logic->timer, logic->thread);
}

void
udap_logic_queue_job(struct udap_logic* logic, struct udap_thread_job job)
{
  udap_thread_job j;
  j.user = job.user;
  j.work = job.work;
  udap_threadpool_queue_job(logic->thread, j);
}

uint32_t
udap_logic_call_later(struct udap_logic* logic, struct udap_timeout_job job)
{
  udap_timeout_job j;
  j.user    = job.user;
  j.timeout = job.timeout;
  j.handler = job.handler;
  return udap_timer_call_later(logic->timer, j);
}

void
udap_logic_cancel_call(struct udap_logic* logic, uint32_t id)
{
  udap_timer_cancel_job(logic->timer, id);
}

void
udap_logic_remove_call(struct udap_logic* logic, uint32_t id)
{
  udap_timer_remove_job(logic->timer, id);
}
}
