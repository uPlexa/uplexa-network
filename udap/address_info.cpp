#include "address_info.hpp"
#include <arpa/inet.h>
#include <udap/bencode.h>
#include <udap/mem.h>
#include <udap/string.h>

static bool
udap_ai_decode_key(struct dict_reader *r, udap_buffer_t *key)
{
  uint64_t i;
  char tmp[128] = {0};

  udap_buffer_t strbuf;
  udap_ai *ai = static_cast< udap_ai * >(r->user);

  // done
  if(!key)
    return true;

  // rank
  if(udap_buffer_eq(*key, "c"))
  {
    if(!bencode_read_integer(r->buffer, &i))
      return false;

    if(i > 65536 || i <= 0)
      return false;

    ai->rank = i;
    return true;
  }

  // dialect
  if(udap_buffer_eq(*key, "d"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;

    if(strbuf.sz >= sizeof(ai->dialect))
      return false;

    memcpy(ai->dialect, strbuf.base, strbuf.sz);
    ai->dialect[strbuf.sz] = 0;
    return true;
  }

  // encryption public key
  if(udap_buffer_eq(*key, "e"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;

    if(strbuf.sz != PUBKEYSIZE)
      return false;

    memcpy(ai->enc_key, strbuf.base, PUBKEYSIZE);
    return true;
  }

  // ip address
  if(udap_buffer_eq(*key, "i"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;

    if(strbuf.sz >= sizeof(tmp))
      return false;

    memcpy(tmp, strbuf.base, strbuf.sz);
    tmp[strbuf.sz] = 0;
    return inet_pton(AF_INET6, tmp, &ai->ip.s6_addr[0]) == 1;
  }

  // port
  if(udap_buffer_eq(*key, "p"))
  {
    if(!bencode_read_integer(r->buffer, &i))
      return false;

    if(i > 65536 || i <= 0)
      return false;

    ai->port = i;
    return true;
  }

  // version
  if(udap_buffer_eq(*key, "v"))
  {
    if(!bencode_read_integer(r->buffer, &i))
      return false;
    return i == UDAP_PROTO_VERSION;
  }

  // bad key
  return false;
}

static bool
udap_ai_list_bdecode_item(struct list_reader *r, bool more)
{
  if(!more)
    return true;
  udap_ai_list *l = static_cast< udap_ai_list * >(r->user);
  udap_ai ai;

  if(!udap_ai_bdecode(&ai, r->buffer))
    return false;

  udap_ai_list_pushback(l, &ai);
  return true;
}

static bool
udap_ai_list_iter_bencode(struct udap_ai_list_iter *iter, struct udap_ai *ai)
{
  return udap_ai_bencode(ai, static_cast< udap_buffer_t * >(iter->user));
}

extern "C" {

bool
udap_ai_bdecode(struct udap_ai *ai, udap_buffer_t *buff)
{
  struct dict_reader reader = {
      .buffer = nullptr, .user = ai, .on_key = &udap_ai_decode_key};
  return bencode_read_dict(buff, &reader);
}

bool
udap_ai_bencode(struct udap_ai *ai, udap_buffer_t *buff)
{
  char ipbuff[128] = {0};
  const char *ipstr;
  if(!bencode_start_dict(buff))
    return false;
  /* rank */
  if(!bencode_write_bytestring(buff, "c", 1))
    return false;
  if(!bencode_write_uint16(buff, ai->rank))
    return false;
  /* dialect */
  if(!bencode_write_bytestring(buff, "d", 1))
    return false;
  if(!bencode_write_bytestring(buff, ai->dialect,
                               strnlen(ai->dialect, sizeof(ai->dialect))))
    return false;
  /* encryption key */
  if(!bencode_write_bytestring(buff, "e", 1))
    return false;
  if(!bencode_write_bytestring(buff, ai->enc_key, PUBKEYSIZE))
    return false;
  /** ip */
  ipstr = inet_ntop(AF_INET6, &ai->ip, ipbuff, sizeof(ipbuff));
  if(!ipstr)
    return false;
  if(!bencode_write_bytestring(buff, "i", 1))
    return false;
  if(!bencode_write_bytestring(buff, ipstr, strnlen(ipstr, sizeof(ipbuff))))
    return false;
  /** port */
  if(!bencode_write_bytestring(buff, "p", 1))
    return false;
  if(!bencode_write_uint16(buff, ai->port))
    return false;

  /** version */
  if(!bencode_write_version_entry(buff))
    return false;
  /** end */
  return bencode_end(buff);
}

bool
udap_ai_list_bencode(struct udap_ai_list *l, udap_buffer_t *buff)
{
  if(!bencode_start_list(buff))
    return false;
  struct udap_ai_list_iter ai_itr = {
      .user = buff, .list = nullptr, .visit = &udap_ai_list_iter_bencode};
  udap_ai_list_iterate(l, &ai_itr);
  return bencode_end(buff);
}

struct udap_ai_list *
udap_ai_list_new()
{
  return new udap_ai_list;
}

void
udap_ai_list_free(struct udap_ai_list *l)
{
  if(l)
  {
    l->list.clear();
    delete l;
  }
}

void
udap_ai_copy(struct udap_ai *dst, struct udap_ai *src)
{
  memcpy(dst, src, sizeof(struct udap_ai));
}

void
udap_ai_list_copy(struct udap_ai_list *dst, struct udap_ai_list *src)
{
  dst->list.clear();
  for(auto &itr : src->list)
    dst->list.emplace_back(itr);
}

void
udap_ai_list_pushback(struct udap_ai_list *l, struct udap_ai *ai)
{
  l->list.push_back(*ai);
}

void
udap_ai_list_iterate(struct udap_ai_list *l, struct udap_ai_list_iter *itr)
{
  itr->list = l;
  for(auto &ai : l->list)
    if(!itr->visit(itr, &ai))
      return;
}

bool
udap_ai_list_index(struct udap_ai_list *l, ssize_t idx, struct udap_ai *dst)
{
  // TODO: implement negative indexes
  if(idx < 0)
    return false;

  size_t i = idx;

  if(l->list.size() > i)
  {
    udap_ai_copy(dst, &l->list[i]);
    return true;
  }
  return false;
}

bool
udap_ai_list_bdecode(struct udap_ai_list *l, udap_buffer_t *buff)
{
  struct list_reader r = {
      .buffer = nullptr, .user = l, .on_item = &udap_ai_list_bdecode_item};
  return bencode_read_list(buff, &r);
}
}
