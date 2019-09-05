#ifndef UDAP_AI_H
#define UDAP_AI_H
#include <udap/crypto.h>
#include <udap/mem.h>
#include <udap/net.h>
#include <stdbool.h>

/**
 * address_info.h
 *
 * utilities for handling addresses on the udap network
 */

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_AI_DIALECT_SIZE 5

/// address information model
struct udap_ai
{
  uint16_t rank;
  char dialect[MAX_AI_DIALECT_SIZE + 1];
  byte_t enc_key[PUBKEYSIZE];
  struct in6_addr ip;
  uint16_t port;
};

/// convert address information struct to bencoded buffer
bool
udap_ai_bencode(struct udap_ai *ai, udap_buffer_t *buff);

/// convert bencoded buffer to address information struct
bool
udap_ai_bdecode(struct udap_ai *ai, udap_buffer_t *buff);

struct udap_ai_list;

/// list of address information initialization
struct udap_ai_list *
udap_ai_list_new();

/// list of address information destruction
void
udap_ai_list_free(struct udap_ai_list *l);

/// copy AI
void
udap_ai_copy(struct udap_ai *dst, struct udap_ai *src);

/// convert udap_ai_list struct to bencoded buffer
bool
udap_ai_list_bencode(struct udap_ai_list *l, udap_buffer_t *buff);

/// convert bencoded buffer to udap_ai_list struct
bool
udap_ai_list_bdecode(struct udap_ai_list *l, udap_buffer_t *buff);

/// return and remove first element from ai_list
struct udap_ai
udap_ai_list_popfront(struct udap_ai_list *l);

/// pushes a copy of ai to the end of the list
void
udap_ai_list_pushback(struct udap_ai_list *l, struct udap_ai *ai);

/// get the number of entries in list
size_t
udap_ai_list_size(struct udap_ai_list *l);

void
udap_ai_list_copy(struct udap_ai_list *dst, struct udap_ai_list *src);

/// does this index exist in list
bool
udap_ai_list_index(struct udap_ai_list *l, ssize_t idx,
                    struct udap_ai *result);

/// ai_list iterator configuration
struct udap_ai_list_iter
{
  /// a customizable pointer to pass data to iteration functor
  void *user;
  /// set by udap_ai_list_iterate()
  struct udap_ai_list *list;
  /// return false to break iteration early
  bool (*visit)(struct udap_ai_list_iter *, struct udap_ai *);
};

/// iterator over list and call visit functor
void
udap_ai_list_iterate(struct udap_ai_list *l, struct udap_ai_list_iter *iter);

#ifdef __cplusplus
}
#endif

#endif
