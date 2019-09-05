#include <udap/bencode.h>
#include <udap/router_contact.h>
#include <udap/version.h>
#include <udap/crypto.hpp>
#include "buffer.hpp"
#include "logger.hpp"

extern "C" {
void
udap_rc_free(struct udap_rc *rc)
{
  if(rc->exits)
    udap_xi_list_free(rc->exits);
  if(rc->addrs)
    udap_ai_list_free(rc->addrs);

  rc->exits = 0;
  rc->addrs = 0;
}

struct udap_rc_decoder
{
  struct udap_rc *rc;
  struct udap_alloc *mem;
};

static bool
udap_rc_decode_dict(struct dict_reader *r, udap_buffer_t *key)
{
  uint64_t v;
  udap_buffer_t strbuf;
  udap_rc *rc = static_cast< udap_rc * >(r->user);

  if(!key)
    return true;

  if(udap_buffer_eq(*key, "a"))
  {
    if(rc->addrs)
    {
      udap_ai_list_free(rc->addrs);
    }
    rc->addrs = udap_ai_list_new();
    return udap_ai_list_bdecode(rc->addrs, r->buffer);
  }

  if(udap_buffer_eq(*key, "k"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz != PUBKEYSIZE)
      return false;
    memcpy(rc->pubkey, strbuf.base, PUBKEYSIZE);
    return true;
  }

  if(udap_buffer_eq(*key, "p"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz != PUBKEYSIZE)
      return false;
    memcpy(rc->enckey, strbuf.base, PUBKEYSIZE);
    return true;
  }

  if(udap_buffer_eq(*key, "u"))
  {
    if(!bencode_read_integer(r->buffer, &rc->last_updated))
      return false;
    return true;
  }

  if(udap_buffer_eq(*key, "v"))
  {
    if(!bencode_read_integer(r->buffer, &v))
      return false;
    return v == UDAP_PROTO_VERSION;
  }

  if(udap_buffer_eq(*key, "x"))
  {
    if(rc->exits)
    {
      udap_xi_list_free(rc->exits);
    }
    rc->exits = udap_xi_list_new();
    return udap_xi_list_bdecode(rc->exits, r->buffer);
  }

  if(udap_buffer_eq(*key, "z"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz != SIGSIZE)
      return false;
    memcpy(rc->signature, strbuf.base, SIGSIZE);
    return true;
  }

  return false;
}

void
udap_rc_copy(struct udap_rc *dst, const struct udap_rc *src)
{
  udap_rc_free(dst);
  udap_rc_clear(dst);
  memcpy(dst->pubkey, src->pubkey, PUBKEYSIZE);
  memcpy(dst->enckey, src->enckey, PUBKEYSIZE);
  memcpy(dst->signature, src->signature, SIGSIZE);
  dst->last_updated = src->last_updated;

  if(src->addrs)
  {
    dst->addrs = udap_ai_list_new();
    udap_ai_list_copy(dst->addrs, src->addrs);
  }
  if(src->exits)
  {
    dst->exits = udap_xi_list_new();
    udap_xi_list_copy(dst->exits, src->exits);
  }
}

bool
udap_rc_bdecode(struct udap_rc *rc, udap_buffer_t *buff)
{
  dict_reader r = {buff, rc, &udap_rc_decode_dict};
  return bencode_read_dict(buff, &r);
}

bool
udap_rc_verify_sig(struct udap_crypto *crypto, struct udap_rc *rc)
{
  // maybe we should copy rc before modifying it
  // would that make it more thread safe?
  // jeff agrees
  bool result = false;
  udap::Signature sig;
  byte_t tmp[MAX_RC_SIZE];

  auto buf = udap::StackBuffer< decltype(tmp) >(tmp);
  // copy sig
  memcpy(sig, rc->signature, SIGSIZE);
  // zero sig
  size_t sz = 0;
  while(sz < SIGSIZE)
    rc->signature[sz++] = 0;

  // bencode
  if(udap_rc_bencode(rc, &buf))
  {
    buf.sz  = buf.cur - buf.base;
    buf.cur = buf.base;
    result  = crypto->verify(rc->pubkey, buf, sig);
  }
  else
    udap::Warn("RC encode failed");
  // restore sig
  memcpy(rc->signature, sig, SIGSIZE);
  return result;
}

bool
udap_rc_bencode(const struct udap_rc *rc, udap_buffer_t *buff)
{
  /* write dict begin */
  if(!bencode_start_dict(buff))
    return false;

  if(rc->addrs)
  {
    /* write ai if they exist */
    if(!bencode_write_bytestring(buff, "a", 1))
      return false;
    if(!udap_ai_list_bencode(rc->addrs, buff))
      return false;
  }

  /* write signing pubkey */
  if(!bencode_write_bytestring(buff, "k", 1))
    return false;
  if(!bencode_write_bytestring(buff, rc->pubkey, PUBKEYSIZE))
    return false;

  /* write encryption pubkey */
  if(!bencode_write_bytestring(buff, "p", 1))
    return false;
  if(!bencode_write_bytestring(buff, rc->enckey, PUBKEYSIZE))
    return false;

  /* write last updated */
  if(!bencode_write_bytestring(buff, "u", 1))
    return false;
  if(!bencode_write_uint64(buff, rc->last_updated))
    return false;

  /* write version */
  if(!bencode_write_version_entry(buff))
    return false;

  if(rc->exits)
  {
    /* write ai if they exist */
    if(!bencode_write_bytestring(buff, "x", 1))
      return false;
    if(!udap_xi_list_bencode(rc->exits, buff))
      return false;
  }

  /* write signature */
  if(!bencode_write_bytestring(buff, "z", 1))
    return false;
  if(!bencode_write_bytestring(buff, rc->signature, SIGSIZE))
    return false;
  return bencode_end(buff);
}
}
