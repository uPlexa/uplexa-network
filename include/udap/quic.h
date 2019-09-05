#ifndef UDAP_QUIC_H_
#define UDAP_QUIC_H_

#include <udap/link.h>

#ifdef __cplusplus
extern "C" {
#endif

struct udap_quic_args
{
};

bool
quic_link_init(struct udap_link* link, struct udap_quic_args args,
               struct udap_msg_muxer* muxer);

#ifdef __cplusplus
}
#endif
#endif
