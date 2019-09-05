#ifndef UDAP_TIME_H
#define UDAP_TIME_H
#include <udap/types.h>
#ifdef __cplusplus
extern "C" {
#endif

udap_time_t
udap_time_now_ms();
udap_seconds_t
udap_time_now_sec();

#ifdef __cplusplus
}
#endif
#endif
