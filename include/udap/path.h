#ifndef UDAP_PATH_H
#define UDAP_PATH_H

#include <udap/router_contact.h>

#define MAXHOPS (8)
#define DEFAULT_PATH_LIFETIME (10 * 60 * 1000)
#define PATH_BUILD_TIMEOUT (30 * 1000)

#ifdef __cplusplus
extern "C" {
#endif

struct udap_path_hop
{
  struct udap_rc router;
  byte_t nextHop[PUBKEYSIZE];
  byte_t sessionkey[SHAREDKEYSIZE];
  byte_t pathid[PATHIDSIZE];
};

struct udap_path_hops
{
  struct udap_path_hop hops[MAXHOPS];
  size_t numHops;
};

void
udap_path_hops_free(struct udap_path_hops* hops);

#ifdef __cplusplus
}
#endif
#endif