#ifndef UDAP_CONFIG_H_
#define UDAP_CONFIG_H_

/**
 * config.h
 *
 * library configuration utilties
 */

#ifdef __cplusplus
extern "C" {
#endif

struct udap_config;

/// allocate config
void
udap_new_config(struct udap_config **conf);

/// deallocate config
void
udap_free_config(struct udap_config **conf);

/// @brief return -1 on fail otherwiwse 0
int
udap_load_config(struct udap_config *conf, const char *fname);

/// config iterator configuration
struct udap_config_iterator
{
  /// a customizable pointer to pass data to iteration functor
  void *user;
  /// set by udap_config_iter
  struct udap_config *conf;
  /// visit (self, section, key, value)
  void (*visit)(struct udap_config_iterator *, const char *, const char *,
                const char *);
};

/// iterator over "conf" and call visit functor defined in "iter"
void
udap_config_iter(struct udap_config *conf,
                  struct udap_config_iterator *iter);

#ifdef __cplusplus
}
#endif
#endif
