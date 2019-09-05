#ifndef UDAP_RC_H
#define UDAP_RC_H
#include <udap/address_info.h>
#include <udap/crypto.h>
#include <udap/exit_info.h>
#ifdef __cplusplus
extern "C" {
#endif

// forward declare
struct udap_alloc;
struct udap_rc;

#define MAX_RC_SIZE (1024)

bool
udap_rc_bdecode(struct udap_rc *rc, udap_buffer_t *buf);
bool
udap_rc_bencode(const struct udap_rc *rc, udap_buffer_t *buf);

struct udap_rc
{
  struct udap_ai_list *addrs;
  // public encryption public key
  byte_t enckey[PUBKEYSIZE];
  // public signing public key
  byte_t pubkey[PUBKEYSIZE];
  struct udap_xi_list *exits;
  byte_t signature[SIGSIZE];
  uint64_t last_updated;

#ifdef __cplusplus
  bool
  BEncode(udap_buffer_t *buf) const
  {
    return udap_rc_bencode(this, buf);
  }

  bool
  BDecode(udap_buffer_t *buf)
  {
    return udap_rc_bdecode(this, buf);
  }
#endif
};

void
udap_rc_free(struct udap_rc *rc);

bool
udap_rc_verify_sig(struct udap_crypto *crypto, struct udap_rc *rc);

void
udap_rc_copy(struct udap_rc *dst, const struct udap_rc *src);

void
udap_rc_set_addrs(struct udap_rc *rc, struct udap_alloc *mem,
                   struct udap_ai_list *addr);

void
udap_rc_set_pubenckey(struct udap_rc *rc, const uint8_t *pubenckey);

void
udap_rc_set_pubsigkey(struct udap_rc *rc, const uint8_t *pubkey);

/// combo
void
udap_rc_set_pubkey(struct udap_rc *rc, const uint8_t *pubenckey,
                    const uint8_t *pubsigkey);

void
udap_rc_sign(struct udap_crypto *crypto, const byte_t *seckey,
              struct udap_rc *rc);

void
udap_rc_clear(struct udap_rc *rc);

bool
udap_rc_addr_list_iter(struct udap_ai_list_iter *iter, struct udap_ai *ai);

struct udap_rc *
udap_rc_read(const char *fpath);

bool
udap_rc_write(struct udap_rc *rc, const char *our_rc_file);

#ifdef __cplusplus
}
#endif
#endif
