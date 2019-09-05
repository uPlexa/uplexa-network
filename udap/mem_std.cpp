#define NO_JEMALLOC
#include <udap/mem.h>
#include <cstdlib>
#include <cstring>

struct udap_alloc
{
  void *(*alloc)(struct udap_alloc *mem, size_t sz, size_t align);
  void (*free)(struct udap_alloc *mem, void *ptr);
};

namespace udap
{
  void *
  std_malloc(struct udap_alloc *mem, size_t sz, size_t align)
  {
    (void)mem;
    (void)align;
    void *ptr = malloc(sz);
    if(ptr)
    {
      std::memset(ptr, 0, sz);
      return ptr;
    }
    abort();
  }

  void
  std_free(struct udap_alloc *mem, void *ptr)
  {
    (void)mem;
    if(ptr)
      free(ptr);
  }

}  // namespace udap

extern "C" {
void
udap_mem_stdlib(struct udap_alloc *mem)
{
  mem->alloc = udap::std_malloc;
  mem->free  = udap::std_free;
}
}
