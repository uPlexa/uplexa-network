#ifndef UDAP_EV_H
#define UDAP_EV_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

/**
 * ev.h
 *
 * event handler (cross platform high performance event system for IO)
 */

#ifdef __cplusplus
extern "C" {
#endif

// forward declare
struct udap_threadpool;
struct udap_logic;

struct udap_ev_loop;

/// allocator
void
udap_ev_loop_alloc(struct udap_ev_loop **ev);

// deallocator
void
udap_ev_loop_free(struct udap_ev_loop **ev);

/// run main loop
int
udap_ev_loop_run(struct udap_ev_loop *ev);

void
udap_ev_loop_run_single_process(struct udap_ev_loop *ev,
                                 struct udap_threadpool *tp,
                                 struct udap_logic *logic);

/// stop event loop and wait for it to complete all jobs
void
udap_ev_loop_stop(struct udap_ev_loop *ev);

/// UDP handling configuration
struct udap_udp_io
{
  void *user;
  void *impl;
  struct udap_ev_loop *parent;
  /// called every event loop tick after reads
  void (*tick)(struct udap_udp_io *);
  void (*recvfrom)(struct udap_udp_io *, const struct sockaddr *, const void *,
                   ssize_t);
};

/// add UDP handler
int
udap_ev_add_udp(struct udap_ev_loop *ev, struct udap_udp_io *udp,
                 const struct sockaddr *src);

/// schedule UDP packet
int
udap_ev_udp_sendto(struct udap_udp_io *udp, const struct sockaddr *to,
                    const void *data, size_t sz);

/// close UDP handler
int
udap_ev_close_udp(struct udap_udp_io *udp);

#ifdef __cplusplus
}
#endif
#endif
