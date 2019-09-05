#include <udap/ev.h>
#include <udap/logic.h>
#include "mem.hpp"

#ifdef __linux__
#include "ev_epoll.hpp"
#endif
#if(__APPLE__ && __MACH__)
#include "ev_kqueue.hpp"
#endif
#ifdef __FreeBSD__
#include "ev_kqueue.hpp"
#endif

extern "C" {
void
udap_ev_loop_alloc(struct udap_ev_loop **ev)
{
#ifdef __linux__
  *ev = new udap_epoll_loop;
#endif
#if(__APPLE__ && __MACH__)
  *ev = new udap_kqueue_loop;
#endif
#ifdef __FreeBSD__
  *ev = new udap_kqueue_loop;
#endif
  (*ev)->init();
}

void
udap_ev_loop_free(struct udap_ev_loop **ev)
{
  delete *ev;
  *ev = nullptr;
}

int
udap_ev_loop_run(struct udap_ev_loop *ev)
{
  return ev->run();
}

void
udap_ev_loop_run_single_process(struct udap_ev_loop *ev,
                                 struct udap_threadpool *tp,
                                 struct udap_logic *logic)
{
  while(true)
  {
    if(ev->tick(10) == -1)
      return;
    udap_logic_tick(logic);
    udap_threadpool_tick(tp);
  }
}

int
udap_ev_add_udp(struct udap_ev_loop *ev, struct udap_udp_io *udp,
                 const struct sockaddr *src)
{
  udp->parent = ev;
  if(ev->udp_listen(udp, src))
    return 0;
  return -1;
}

int
udap_ev_close_udp(struct udap_udp_io *udp)
{
  if(udp->parent->udp_close(udp))
    return 0;
  return -1;
}

void
udap_ev_loop_stop(struct udap_ev_loop *loop)
{
  loop->stop();
}

int
udap_ev_udp_sendto(struct udap_udp_io *udp, const sockaddr *to,
                    const void *buf, size_t sz)
{
  return static_cast< udap::ev_io * >(udp->impl)->sendto(to, buf, sz);
}
}
