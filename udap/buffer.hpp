#ifndef UDAP_BUFFER_HPP
#define UDAP_BUFFER_HPP

#include <udap/buffer.h>

namespace udap
{
  /** initialize udap_buffer_t from stack allocated buffer */
  template < typename T >
  void
  StackBuffer(udap_buffer_t& buff, T& stack)
  {
    buff.base = stack;
    buff.cur  = buff.base;
    buff.sz   = sizeof(stack);
  }

  template < typename T >
  udap_buffer_t
  StackBuffer(T& stack)
  {
    udap_buffer_t buff;
    buff.base = &stack[0];
    buff.cur  = buff.base;
    buff.sz   = sizeof(stack);
    return buff;
  }

  /** initialize udap_buffer_t from container */
  template < typename T >
  udap_buffer_t
  Buffer(T& t)
  {
    udap_buffer_t buff;
    buff.base = &t[0];
    buff.cur  = buff.base;
    buff.sz   = t.size();
    return buff;
  }
}

#endif
