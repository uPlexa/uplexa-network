#ifndef UDAP_PATHFINDER_H_
#define UDAP_PATHFINDER_H_

#include <udap/buffer.h>
#include <udap/path.h>

/**
 * path_base.h
 *
 * path api functions
 */

#ifdef __cplusplus
extern "C" {
#endif

/// forard declare
struct udap_router;
struct udap_dht_context;

// fwd declr
struct udap_pathbuilder_context;

/// alloc
struct udap_pathbuilder_context*
udap_pathbuilder_context_new(struct udap_router* router,
                              struct udap_dht_context* dht);
/// dealloc
void
udap_pathbuilder_context_free(struct udap_pathbuilder_context* ctx);

// fwd declr
struct udap_pathbuild_job;

/// response callback
typedef void (*udap_pathbuilder_hook)(struct udap_pathbuild_job*);
// select hop function (nodedb, prevhop, result, hopnnumber) called in logic
// thread
typedef void (*udap_pathbuilder_select_hop_func)(struct udap_nodedb*,
                                                  struct udap_rc*,
                                                  struct udap_rc*, size_t);

// request struct
struct udap_pathbuild_job
{
  // opaque pointer for user data
  void* user;
  // router context (set by udap_pathbuilder_build_path)
  struct udap_router* router;
  // context
  struct udap_pathbuilder_context* context;
  // path hop selection
  udap_pathbuilder_select_hop_func selectHop;
  // called when the path build started
  udap_pathbuilder_hook pathBuildStarted;
  // path
  struct udap_path_hops hops;
};

/// request func
// or find_path but thought pathfinder_find_path was a bit redundant
void
udap_pathbuilder_build_path(struct udap_pathbuild_job* job);

#ifdef __cplusplus
}
#endif
#endif
