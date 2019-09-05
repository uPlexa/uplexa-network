#ifndef UDAP_THREADPOOL_H
#define UDAP_THREADPOOL_H
#ifdef __cplusplus
extern "C" {
#endif

struct udap_threadpool;

struct udap_threadpool *
udap_init_threadpool(int workers, const char *name);

/// for single process mode
struct udap_threadpool *
udap_init_same_process_threadpool();

void
udap_free_threadpool(struct udap_threadpool **tp);

typedef void (*udap_thread_work_func)(void *);

/** job to be done in worker thread */
struct udap_thread_job
{
  /** user data to pass to work function */
  void *user;
  /** called in threadpool worker thread */
  udap_thread_work_func work;

#ifdef __cplusplus

  udap_thread_job(void *u, udap_thread_work_func w) : user(u), work(w)
  {
  }

  udap_thread_job() : user(nullptr), work(nullptr)
  {
  }

#endif
};

/// for single process mode
void
udap_threadpool_tick(struct udap_threadpool *tp);

void
udap_threadpool_queue_job(struct udap_threadpool *tp,
                           struct udap_thread_job j);

void
udap_threadpool_stop(struct udap_threadpool *tp);
void
udap_threadpool_join(struct udap_threadpool *tp);

void
udap_threadpool_wait(struct udap_threadpool *tp);

#ifdef __cplusplus
}
#endif

#endif
