#include <udap/time.h>
#include <udap/timer.h>
#include <atomic>
#include <condition_variable>
#include <list>
#include <unordered_map>

#include "logger.hpp"

namespace udap
{
  struct timer
  {
    void* user;
    uint64_t called_at;
    uint64_t started;
    uint64_t timeout;
    udap_timer_handler_func func;
    bool done;
    bool canceled;

    timer(uint64_t ms = 0, void* _user = nullptr,
          udap_timer_handler_func _func = nullptr)
        : user(_user)
        , called_at(0)
        , started(udap_time_now_ms())
        , timeout(ms)
        , func(_func)
        , done(false)
        , canceled(false)
    {
    }

    ~timer()
    {
    }

    void
    exec();

    static void
    call(void* user)
    {
      static_cast< timer* >(user)->exec();
    }

    void
    send_job(udap_threadpool* pool)
    {
      udap_threadpool_queue_job(pool, {this, timer::call});
    }
  };
};  // namespace udap

struct udap_timer_context
{
  std::mutex timersMutex;
  std::unordered_map< uint32_t, udap::timer* > timers;
  std::mutex tickerMutex;
  std::condition_variable* ticker       = nullptr;
  std::chrono::milliseconds nextTickLen = std::chrono::milliseconds(100);

  uint32_t ids = 0;
  bool _run    = true;

  ~udap_timer_context()
  {
    if(ticker)
      delete ticker;
  }

  bool
  run()
  {
    return _run;
  }

  void
  stop()
  {
    _run = false;
  }

  void
  cancel(uint32_t id)
  {
    std::unique_lock< std::mutex > lock(timersMutex);
    auto itr = timers.find(id);
    if(itr == timers.end())
      return;
    itr->second->canceled = true;
  }

  void
  remove(uint32_t id)
  {
    std::unique_lock< std::mutex > lock(timersMutex);
    auto itr = timers.find(id);
    if(itr == timers.end())
      return;
    itr->second->func     = nullptr;
    itr->second->canceled = true;
  }

  uint32_t
  call_later(void* user, udap_timer_handler_func func, uint64_t timeout_ms)
  {
    std::unique_lock< std::mutex > lock(timersMutex);
    uint32_t id = ++ids;
    timers[id]  = new udap::timer(timeout_ms, user, func);
    return id;
  }

  void
  cancel_all()
  {
    std::list< uint32_t > ids;

    {
      std::unique_lock< std::mutex > lock(timersMutex);

      for(auto& item : timers)
      {
        ids.push_back(item.first);
      }
    }

    for(auto id : ids)
    {
      cancel(id);
    }
  }
};

extern "C" {

struct udap_timer_context*
udap_init_timer()
{
  return new udap_timer_context;
}

uint32_t
udap_timer_call_later(struct udap_timer_context* t,
                       struct udap_timeout_job job)
{
  return t->call_later(job.user, job.handler, job.timeout);
}

void
udap_free_timer(struct udap_timer_context** t)
{
  if(*t)
    delete *t;
  *t = nullptr;
}

void
udap_timer_remove_job(struct udap_timer_context* t, uint32_t id)
{
  t->remove(id);
}

void
udap_timer_stop(struct udap_timer_context* t)
{
  // destroy all timers
  // don't call callbacks on timers
  t->timers.clear();
  t->stop();
  if(t->ticker)
    t->ticker->notify_all();
}

void
udap_timer_cancel_job(struct udap_timer_context* t, uint32_t id)
{
  t->cancel(id);
}

void
udap_timer_tick_all(struct udap_timer_context* t,
                     struct udap_threadpool* pool)
{
  if(!t->run())
    return;
  auto now = udap_time_now_ms();
  auto itr = t->timers.begin();
  while(itr != t->timers.end())
  {
    if(now - itr->second->started >= itr->second->timeout
       || itr->second->canceled)
    {
      if(itr->second->func && itr->second->called_at == 0)
      {
        // timer hit
        itr->second->called_at = now;
        itr->second->send_job(pool);
        ++itr;
      }
      else if(itr->second->done)
      {
        // remove timer
        udap::timer* timer = itr->second;
        itr                 = t->timers.erase(itr);
        delete timer;
      }
      else
        ++itr;
    }
    else  // timer not hit yet
      ++itr;
  }
}

void
udap_timer_run(struct udap_timer_context* t, struct udap_threadpool* pool)
{
  t->ticker = new std::condition_variable;
  while(t->run())
  {
    // wait for timer mutex
    if(t->ticker)
    {
      std::unique_lock< std::mutex > lock(t->tickerMutex);
      t->ticker->wait_for(lock, t->nextTickLen);
    }

    if(t->run())
    {
      std::unique_lock< std::mutex > lock(t->timersMutex);
      // we woke up
      udap_timer_tick_all(t, pool);
    }
  }
}
}

namespace udap
{
  void
  timer::exec()
  {
    if(func)
    {
      auto diff = called_at - started;
      // zero out function pointer before call to prevent multiple calls being
      // queued if call takes longer than 1 timer tick
      auto call = func;
      func      = nullptr;
      if(diff >= timeout)
        call(user, timeout, 0);
      else
        call(user, timeout, diff);
    }
    done = true;
  }
}
