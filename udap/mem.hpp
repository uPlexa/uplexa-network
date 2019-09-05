#ifndef UDAP_MEM_HPP
#define UDAP_MEM_HPP
#include <udap/buffer.h>
#include <udap/mem.h>
#include <stdio.h>

namespace udap
{
  void
  Zero(void *ptr, size_t sz);

  template < typename T >
  void
  dumphex(const uint8_t *t)
  {
    size_t idx = 0;
    while(idx < sizeof(T))
    {
      printf("%.2x ", t[idx++]);
      if(idx % 8 == 0)
        printf("\n");
    }
  }

  template < typename T >
  void
  dumphex_buffer(T buff)
  {
    size_t idx = 0;
    printf("buffer of size %ld\n", buff.sz);
    while(idx < buff.sz)
    {
      printf("%.2x ", buff.base[idx++]);
      if(idx % 8 == 0)
        printf("\n");
    }
  }

}  // namespace udap

#endif
