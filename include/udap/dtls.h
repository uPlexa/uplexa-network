#ifndef UDAP_DTLS_H_
#define UDAP_DTLS_H_

#include <udap/link.h>
#include <udap/mem.h>

/**
 * dtls.h
 *
 * Datagram TLS functions
 * https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security for more info
 * on DTLS
 */

#ifdef __cplusplus
extern "C" {
#endif

/// DTLS configuration
struct udap_dtls_args
{
  struct udap_alloc* mem;
  const char* keyfile;
  const char* certfile;
};

/// allocator
void
dtls_link_init(struct udap_link* link, struct udap_dtls_args args,
               struct udap_msg_muxer* muxer);

#ifdef __cplusplus
}
#endif
#endif
