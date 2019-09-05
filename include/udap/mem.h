#ifndef UDAP_MEM_H_
#define UDAP_MEM_H_
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** constant time memcmp */
bool
udap_eq(const void *a, const void *b, size_t sz);

#ifdef __cplusplus
}
#endif

#endif
