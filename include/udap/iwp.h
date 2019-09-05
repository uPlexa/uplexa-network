#ifndef UDAP_IWP_H_
#define UDAP_IWP_H_
#include <udap/crypto.h>
#include <udap/link.h>

#ifdef __cplusplus
extern "C" {
#endif

struct udap_iwp_args
{
  struct udap_crypto* crypto;
  struct udap_logic* logic;
  struct udap_threadpool* cryptoworker;
  struct udap_router* router;
  const char* keyfile;
};

void
iwp_link_init(struct udap_link* link, struct udap_iwp_args args);

#ifdef __cplusplus
}
#endif
#endif
