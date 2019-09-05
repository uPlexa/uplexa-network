#ifndef UDAP_H_
#define UDAP_H_
#include <udap/dht.h>
#include <udap/ev.h>
#include <udap/logic.h>
#include <udap/mem.h>
#include <udap/nodedb.h>
#include <udap/router.h>
#include <udap/version.h>

#ifdef __cplusplus
extern "C" {
#endif

/// udap application context for C api
struct udap_main;

/// initialize application context and load config
struct udap_main *
udap_main_init(const char *fname, bool multiProcess);

/// handle signal for main context
void
udap_main_signal(struct udap_main *ptr, int sig);

/// set custom dht message handler function
void
udap_main_set_dht_handler(struct udap_main *ptr, udap_dht_msg_handler h);

/// run main context
int
udap_main_run(struct udap_main *ptr);

/// load nodeDB into memory
int
udap_main_loadDatabase(struct udap_main *ptr);

/// iterator on nodedb entries
int
udap_main_iterateDatabase(struct udap_main *ptr, struct udap_nodedb_iter i);

/// put RC into nodeDB
bool
udap_main_putDatabase(struct udap_main *ptr, struct udap_rc *rc);

struct udap_rc *
udap_main_getDatabase(struct udap_main *ptr, byte_t *pk);

void
udap_main_free(struct udap_main *ptr);

#ifdef __cplusplus
}
#endif
#endif
