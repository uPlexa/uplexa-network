#ifndef UDAP_XR_H
#define UDAP_XR_H
#include <udap/buffer.h>
#include <udap/net.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

struct udap_xr
{
  struct in6_addr gateway;
  struct in6_addr netmask;
  struct in6_addr source;
  uint64_t lifetime;
};

bool
udap_xr_bencode(struct udap_xr* xr, udap_buffer_t* buff);
bool
udap_xr_bdecode(struct udap_xr* xr, udap_buffer_t* buff);

#ifdef __cplusplus
}
#endif
#endif
