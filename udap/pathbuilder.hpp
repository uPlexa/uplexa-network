#ifndef UDAP_PATHFINDER_HPP_
#define UDAP_PATHFINDER_HPP_
#include <udap/pathbuilder.h>

struct udap_pathbuilder_context : public udap::path::PathSet
{
  struct udap_router* router;
  struct udap_dht_context* dht;
  /// construct
  udap_pathbuilder_context(udap_router* p_router,
                            struct udap_dht_context* p_dht);

  void
  BuildOne();
};

#endif
