#ifndef UDAP_EV_HPP
#define UDAP_EV_HPP
#include <udap/ev.h>

#include <unistd.h>
#include <list>

namespace udap
{
  struct ev_io
  {
    int fd;
    ev_io(int f) : fd(f){};
    virtual int
    read(void* buf, size_t sz) = 0;

    virtual int
    sendto(const sockaddr* dst, const void* data, size_t sz) = 0;
    virtual ~ev_io()
    {
      ::close(fd);
    };
  };
};  // namespace udap

struct udap_ev_loop
{
  virtual bool
  init() = 0;
  virtual int
  run() = 0;

  virtual int
  tick(int ms) = 0;

  virtual void
  stop() = 0;

  virtual bool
  udp_listen(udap_udp_io* l, const sockaddr* src) = 0;
  virtual bool
  udp_close(udap_udp_io* l) = 0;
  virtual bool
  close_ev(udap::ev_io* ev) = 0;

  virtual ~udap_ev_loop(){};

  std::list< udap_udp_io* > udp_listeners;
};

#endif
