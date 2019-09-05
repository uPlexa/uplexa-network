#ifndef UDAP_XI_H
#define UDAP_XI_H
#include <udap/buffer.h>
#include <udap/crypto.h>
#include <udap/net.h>

/**
 * exit_info.h
 *
 * utilities for handling exits on the udap network
 */

#ifdef __cplusplus
extern "C" {
#endif

/// Exit info model
struct udap_xi
{
  struct in6_addr address;
  struct in6_addr netmask;
  byte_t pubkey[PUBKEYSIZE];
};

bool
udap_xi_bdecode(struct udap_xi *xi, udap_buffer_t *buf);
bool
udap_xi_bencode(struct udap_xi *xi, udap_buffer_t *buf);

struct udap_xi_list;

struct udap_xi_list *
udap_xi_list_new();

void
udap_xi_list_free(struct udap_xi_list *l);

bool
udap_xi_list_bdecode(struct udap_xi_list *l, udap_buffer_t *buf);

bool
udap_xi_list_bencode(struct udap_xi_list *l, udap_buffer_t *buf);

void
udap_xi_list_pushback(struct udap_xi_list *l, struct udap_xi *xi);

void
udap_xi_list_copy(struct udap_xi_list *dst, struct udap_xi_list *src);

void
udap_xi_copy(struct udap_xi *dst, struct udap_xi *src);

struct udap_xi_list_iter
{
  void *user;
  struct udap_xi_list *list;
  bool (*visit)(struct udap_xi_list_iter *, struct udap_xi *);
};

void
udap_xi_list_iterate(struct udap_xi_list *l, struct udap_xi_list_iter *iter);

#ifdef __cplusplus
}
#endif
#endif
