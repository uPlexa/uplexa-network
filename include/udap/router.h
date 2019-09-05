#ifndef UDAP_ROUTER_H_
#define UDAP_ROUTER_H_
#include <udap/config.h>
#include <udap/ev.h>
#include <udap/link.h>
#include <udap/logic.h>
#include <udap/nodedb.h>
#include <udap/pathbuilder.h>
#include <udap/router_contact.h>
#include <udap/threadpool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct udap_router;

bool
udap_findOrCreateIdentity(struct udap_crypto *crypto, const char *path,
                           byte_t *secretkey);

struct udap_router *
udap_init_router(struct udap_threadpool *worker,
                  struct udap_ev_loop *netloop, struct udap_logic *logic);
void
udap_free_router(struct udap_router **router);

bool
udap_router_try_connect(struct udap_router *router, struct udap_rc *remote,
                         uint16_t numretries);

/// override default path builder function (FFI)
void
udap_router_override_path_selection(struct udap_router *router,
                                     udap_pathbuilder_select_hop_func func);

bool
udap_configure_router(struct udap_router *router, struct udap_config *conf);

void
udap_run_router(struct udap_router *router, struct udap_nodedb *nodedb);

void
udap_stop_router(struct udap_router *router);

struct udap_router_link_iter
{
  void *user;
  bool (*visit)(struct udap_router_link_iter *, struct udap_router *,
                struct udap_link *);
};

void
udap_router_iterate_links(struct udap_router *router,
                           struct udap_router_link_iter iter);

#ifdef __cplusplus
}
#endif

#endif
