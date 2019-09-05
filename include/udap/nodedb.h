#ifndef UDAP_NODEDB_H
#define UDAP_NODEDB_H
#include <udap/common.h>
#include <udap/crypto.h>
#include <udap/router_contact.h>

/**
 * nodedb.h
 *
 * persistent storage API for router contacts
 */

#ifdef __cplusplus
extern "C" {
#endif

struct udap_nodedb;

/// create an empty nodedb
struct udap_nodedb *
udap_nodedb_new(struct udap_crypto *crypto);

/// free a nodedb and all loaded rc
void
udap_nodedb_free(struct udap_nodedb **n);

/// ensure a nodedb fs skiplist structure is at dir
/// create if not there.
bool
udap_nodedb_ensure_dir(const char *dir);

/// load entire nodedb from fs skiplist at dir
ssize_t
udap_nodedb_load_dir(struct udap_nodedb *n, const char *dir);

/// store entire nodedb to fs skiplist at dir
ssize_t
udap_nodedb_store_dir(struct udap_nodedb *n, const char *dir);

struct udap_nodedb_iter
{
  void *user;
  struct udap_rc *rc;
  size_t index;
  bool (*visit)(struct udap_nodedb_iter *);
};

/// iterate over all loaded rc with an iterator
int
udap_nodedb_iterate_all(struct udap_nodedb *n, struct udap_nodedb_iter i);

/// get a random rc that is loaded
void
udap_nodedb_get_random_rc(struct udap_nodedb *n, struct udap_rc *result);

/// select a random rc at hop number N
void
udap_nodedb_select_random_hop(struct udap_nodedb *n, struct udap_rc *prev,
                               struct udap_rc *result, size_t N);

/// return number of RC loaded
size_t
udap_nodedb_num_loaded(struct udap_nodedb *n);

/**
   put an rc into the node db
   overwrites with new contents if already present
   flushes the single entry to disk
   returns true on success and false on error
 */
bool
udap_nodedb_put_rc(struct udap_nodedb *n, struct udap_rc *rc);

/// return a pointer to an already loaded RC or nullptr if it's not there
struct udap_rc *
udap_nodedb_get_rc(struct udap_nodedb *n, const byte_t *pk);

/// struct for async rc verification
struct udap_async_verify_rc;

typedef void (*udap_async_verify_rc_hook_func)(struct udap_async_verify_rc *);

/// verify rc request
struct udap_async_verify_rc
{
  /// async_verify_context
  void *user;
  /// nodedb storage
  struct udap_nodedb *nodedb;
  // udap_logic for udap_logic_queue_job
  struct udap_logic *logic;  // includes a udap_threadpool
  // struct udap_crypto *crypto; // probably don't need this because we have
  // it in the nodedb
  struct udap_threadpool *cryptoworker;
  struct udap_threadpool *diskworker;

  /// router contact (should this be a pointer?)
  struct udap_rc rc;
  /// result
  bool valid;
  /// hook
  udap_async_verify_rc_hook_func hook;
};

/**
    struct for async rc verification
    data is loaded in disk io threadpool
    crypto is done on the crypto worker threadpool
    result is called on the logic thread
*/
void
udap_nodedb_async_verify(struct udap_async_verify_rc *job);

struct udap_async_load_rc;

typedef void (*udap_async_load_rc_hook_func)(struct udap_async_load_rc *);

struct udap_async_load_rc
{
  /// async_verify_context
  void *user;
  /// nodedb storage
  struct udap_nodedb *nodedb;
  /// udap_logic for calling hook
  struct udap_logic *logic;
  /// disk worker threadpool
  struct udap_threadpool *diskworker;
  /// target pubkey
  byte_t pubkey[PUBKEYSIZE];
  /// router contact result
  struct udap_rc rc;
  /// set to true if we loaded the rc
  bool loaded;
  /// hook function called in logic thread
  udap_async_load_rc_hook_func hook;
};

/// asynchronously load an rc from disk
void
udap_nodedb_async_load_rc(struct udap_async_load_rc *job);

#ifdef __cplusplus
}
#endif
#endif
