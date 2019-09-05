#ifndef UDAP_DHT_H_
#define UDAP_DHT_H_

#include <udap/buffer.h>
#include <udap/router.h>

/**
 * dht.h
 *
 * DHT functions
 */

#ifdef __cplusplus
extern "C" {
#endif

struct udap_dht_context;

/// allocator
struct udap_dht_context*
udap_dht_context_new(struct udap_router* parent);

/// deallocator
void
udap_dht_context_free(struct udap_dht_context* dht);

struct udap_dht_msg;

/// handler function
/// f(outmsg, inmsg)
/// returns true if outmsg has been filled otherwise returns false
typedef bool (*udap_dht_msg_handler)(struct udap_dht_msg*,
                                      struct udap_dht_msg*);

/// start dht context with our location in keyspace
void
udap_dht_context_start(struct udap_dht_context* ctx, const byte_t* key);

// override dht message handler with custom handler
void
udap_dht_set_msg_handler(struct udap_dht_context* ctx,
                          udap_dht_msg_handler func);

struct udap_router_lookup_job;

typedef void (*udap_router_lookup_handler)(struct udap_router_lookup_job*);

struct udap_router_lookup_job
{
  void* user;
  udap_router_lookup_handler hook;
  struct udap_dht_context* dht;
  byte_t target[PUBKEYSIZE];
  bool found;
  struct udap_rc result;
};

/// start allowing dht participation on a context
void
udap_dht_allow_transit(struct udap_dht_context* ctx);

/// put router as a dht peer
void
udap_dht_put_peer(struct udap_dht_context* ctx, struct udap_rc* rc);

/// remove router from tracked dht peer list
void
udap_dht_remove_peer(struct udap_dht_context* ctx, const byte_t* id);

void
udap_dht_lookup_router(struct udap_dht_context* ctx,
                        struct udap_router_lookup_job* job);

#ifdef __cplusplus
}
#endif
#endif
