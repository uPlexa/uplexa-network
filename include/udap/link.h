#ifndef UDAP_LINK_H_
#define UDAP_LINK_H_
#include <udap/address_info.h>
#include <udap/crypto.h>
#include <udap/ev.h>
#include <udap/logic.h>
#include <udap/mem.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 2^15 bytes */
#define MAX_LINK_MSG_SIZE (32768)

/**
 * wire layer transport interface
 */
struct udap_link;

/**
 * wire layer transport session for point to point communication between us and
 * another
 */
struct udap_link_session;

/** outbound session establish job */
struct udap_link_establish_job
{
  void *user;
  void (*result)(struct udap_link_establish_job *);
  struct udap_ai ai;
  uint64_t timeout;
  uint16_t retries;

  byte_t pubkey[PUBKEYSIZE];
  /** set on success by try_establish */
  struct udap_link *link;
  /** set on success by try_establish */
  struct udap_link_session *session;
};

struct udap_link_session_iter
{
  void *user;
  struct udap_link *link;
  bool (*visit)(struct udap_link_session_iter *, struct udap_link_session *);
};

struct udap_link_ev_listener
{
  void *user;
  void (*established)(struct udap_link_ev_listener *,
                      struct udap_link_session *, bool);
  void (*timeout)(struct udap_link_ev_listener *, struct udap_link_session *,
                  bool);
  void (*tx)(struct udap_link_ev_listener *, struct udap_link_session *,
             size_t);
  void (*rx)(struct udap_link_ev_listener *, struct udap_link_session *,
             size_t);
  void (*error)(struct udap_link_ev_listener *, struct udap_link_session *,
                const char *);
};

// forward declare
struct udap_router;

struct udap_link
{
  void *impl;
  struct udap_router *router;
  const char *(*name)(void);
  void (*get_our_address)(struct udap_link *, struct udap_ai *);
  /*
  int (*register_listener)(struct udap_link *, struct udap_link_ev_listener);
  void (*deregister_listener)(struct udap_link *, int);
  */
  bool (*configure)(struct udap_link *, struct udap_ev_loop *, const char *,
                    int, uint16_t);
  bool (*start_link)(struct udap_link *, struct udap_logic *);
  bool (*stop_link)(struct udap_link *);
  void (*iter_sessions)(struct udap_link *, struct udap_link_session_iter);
  bool (*try_establish)(struct udap_link *, struct udap_link_establish_job *);
  /// send to already established session given its public identity key
  /// returns false if we don't have this session
  /// returns true if the messages were queued
  bool (*sendto)(struct udap_link *, const byte_t *, udap_buffer_t);
  /// return true if we have a session to router given public identity key
  bool (*has_session_to)(struct udap_link *, const byte_t *);
  void (*mark_session_active)(struct udap_link *, struct udap_link_session *);
  void (*free_impl)(struct udap_link *);
};

/** checks if all members are initialized */
bool
udap_link_initialized(struct udap_link *link);

struct udap_link_session
{
  void *impl;
  /** send an entire message, splits up into smaller pieces and does encryption
   */
  bool (*sendto)(struct udap_link_session *, udap_buffer_t);
  /** return true if this session is timed out */
  bool (*timeout)(struct udap_link_session *);
  /** explicit close session */
  void (*close)(struct udap_link_session *);
  /** set session established */
  void (*established)(struct udap_link_session *);
  /** get parent link */
  struct udap_link *(*get_parent)(struct udap_link_session *);
  /** get router contact of remote router */
  struct udap_rc *(*get_remote_router)(struct udap_link_session *);
};

bool
udap_link_session_initialized(struct udap_link_session *s);

#ifdef __cplusplus
}
#endif
#endif
