#include "threadpool.hpp"
#include <pthread.h>
#include <cstring>

#include <udap/time.h>
#include <queue>

#include "logger.hpp"

#if(__FreeBSD__)
#include <pthread_np.h>
#endif

namespace udap
{
  namespace thread
  {
    Pool::Pool(size_t workers, const char *name)
    {
      stop = false;
      while(workers--)
      {
        threads.emplace_back([this, name] {
          if(name)
          {
#if(__APPLE__ && __MACH__)
            pthread_setname_np(name);
#elif(__FreeBSD__)
            pthread_set_name_np(pthread_self(), name);
#else
            pthread_setname_np(pthread_self(), name);
#endif
          }
          for(;;)
          {
            udap_thread_job *job;
            {
              lock_t lock(this->queue_mutex);
              this->condition.wait(
                  lock, [this] { return this->stop || !this->jobs.empty(); });
              if(this->stop && this->jobs.empty())
                return;
              job = this->jobs.front();
              this->jobs.pop_front();
            }
            auto now = udap_time_now_ms();
            // do work
            job->work(job->user);
            auto after = udap_time_now_ms();
            auto dlt   = after - now;
            if(dlt > 10)
              udap::Warn("work took ", dlt, " ms");
            delete job;
          }
        });
      }
    }

    void
    Pool::Stop()
    {
      {
        lock_t lock(queue_mutex);
        stop = true;
      }
      condition.notify_all();
    }

    void
    Pool::Join()
    {
      for(auto &t : threads)
        t.join();
      threads.clear();
      done.notify_all();
    }

    void
    Pool::QueueJob(const udap_thread_job &job)
    {
      {
        lock_t lock(queue_mutex);

        // don't allow enqueueing after stopping the pool
        if(stop)
          return;

        jobs.push_back(new udap_thread_job(job.user, job.work));
      }
      condition.notify_one();
    }

  }  // namespace thread
}  // namespace udap

struct udap_threadpool
{
  udap::thread::Pool *impl;

  std::queue< udap_thread_job > jobs;

  udap_threadpool(int workers, const char *name)
      : impl(new udap::thread::Pool(workers, name))
  {
  }

  udap_threadpool() : impl(nullptr)
  {
  }
};

extern "C" {

struct udap_threadpool *
udap_init_threadpool(int workers, const char *name)
{
  if(workers > 0)
    return new udap_threadpool(workers, name);
  else
    return nullptr;
}

struct udap_threadpool *
udap_init_same_process_threadpool()
{
  return new udap_threadpool();
}

void
udap_threadpool_join(struct udap_threadpool *pool)
{
  udap::Debug("threadpool join");
  if(pool->impl)
    pool->impl->Join();
}

void
udap_threadpool_start(struct udap_threadpool *pool)
{ /** no op */
}

void
udap_threadpool_stop(struct udap_threadpool *pool)
{
  udap::Debug("threadpool stop");
  if(pool->impl)
    pool->impl->Stop();
}

void
udap_threadpool_wait(struct udap_threadpool *pool)
{
  std::mutex mtx;
  udap::Debug("threadpool wait");
  if(pool->impl)
  {
    std::unique_lock< std::mutex > lock(mtx);
    pool->impl->done.wait(lock);
  }
}

void
udap_threadpool_queue_job(struct udap_threadpool *pool,
                           struct udap_thread_job job)
{
  if(pool->impl)
    pool->impl->QueueJob(job);
  else
    pool->jobs.push(job);
}

void
udap_threadpool_tick(struct udap_threadpool *pool)
{
  while(pool->jobs.size())
  {
    auto &job = pool->jobs.front();
    job.work(job.user);
    pool->jobs.pop();
  }
}

void
udap_free_threadpool(struct udap_threadpool **pool)
{
  if(*pool)
  {
    delete *pool;
  }
  *pool = nullptr;
}
}
