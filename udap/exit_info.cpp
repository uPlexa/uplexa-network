#include <arpa/inet.h>
#include <udap/bencode.h>
#include <udap/exit_info.h>
#include <udap/mem.h>
#include <udap/string.h>
#include <list>

struct udap_xi_list
{
  std::list< udap_xi > list;
};

extern "C" {

struct udap_xi_list *
udap_xi_list_new()
{
  return new udap_xi_list;
}

void
udap_xi_list_free(struct udap_xi_list *l)
{
  if(l)
  {
    delete l;
  }
}

static bool
udap_xi_iter_bencode(struct udap_xi_list_iter *iter, struct udap_xi *xi)
{
  return udap_xi_bencode(xi, static_cast< udap_buffer_t * >(iter->user));
}

bool
udap_xi_list_bencode(struct udap_xi_list *l, udap_buffer_t *buff)
{
  if(!bencode_start_list(buff))
    return false;
  struct udap_xi_list_iter xi_itr = {buff, nullptr, &udap_xi_iter_bencode};
  udap_xi_list_iterate(l, &xi_itr);
  return bencode_end(buff);
}

void
udap_xi_list_iterate(struct udap_xi_list *l, struct udap_xi_list_iter *iter)
{
  iter->list = l;
  for(auto &item : l->list)
    if(!iter->visit(iter, &item))
      return;
}

bool
udap_xi_bencode(struct udap_xi *xi, udap_buffer_t *buff)
{
  char addr_buff[128] = {0};
  const char *addr;
  if(!bencode_start_dict(buff))
    return false;

  /** address */
  addr = inet_ntop(AF_INET6, &xi->address, addr_buff, sizeof(addr_buff));
  if(!addr)
    return false;
  if(!bencode_write_bytestring(buff, "a", 1))
    return false;
  if(!bencode_write_bytestring(buff, addr, strnlen(addr, sizeof(addr_buff))))
    return false;

  /** netmask */
  addr = inet_ntop(AF_INET6, &xi->netmask, addr_buff, sizeof(addr_buff));
  if(!addr)
    return false;
  if(!bencode_write_bytestring(buff, "b", 1))
    return false;
  if(!bencode_write_bytestring(buff, addr, strnlen(addr, sizeof(addr_buff))))
    return false;

  /** public key */
  if(!bencode_write_bytestring(buff, "k", 1))
    return false;
  if(!bencode_write_bytestring(buff, xi->pubkey, PUBKEYSIZE))
    return false;

  /** version */
  if(!bencode_write_version_entry(buff))
    return false;

  return bencode_end(buff);
}

static bool
udap_xi_decode_dict(struct dict_reader *r, udap_buffer_t *key)
{
  if(!key)
    return true;

  udap_xi *xi = static_cast< udap_xi * >(r->user);
  udap_buffer_t strbuf;
  uint64_t v;
  char tmp[128] = {0};

  // address
  if(udap_buffer_eq(*key, "a"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz >= sizeof(tmp))
      return false;
    memcpy(tmp, strbuf.base, strbuf.sz);
    return inet_pton(AF_INET6, tmp, xi->address.s6_addr) == 1;
  }

  if(udap_buffer_eq(*key, "b"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz >= sizeof(tmp))
      return false;
    memcpy(tmp, strbuf.base, strbuf.sz);
    return inet_pton(AF_INET6, tmp, xi->netmask.s6_addr) == 1;
  }

  if(udap_buffer_eq(*key, "k"))
  {
    if(!bencode_read_string(r->buffer, &strbuf))
      return false;
    if(strbuf.sz != PUBKEYSIZE)
      return false;
    memcpy(xi->pubkey, strbuf.base, PUBKEYSIZE);
    return true;
  }

  if(udap_buffer_eq(*key, "v"))
  {
    if(!bencode_read_integer(r->buffer, &v))
      return false;
    return v == UDAP_PROTO_VERSION;
  }

  return false;
}

bool
udap_xi_bdecode(struct udap_xi *xi, udap_buffer_t *buf)
{
  struct dict_reader r = {buf, xi, &udap_xi_decode_dict};
  return bencode_read_dict(buf, &r);
}

void
udap_xi_list_pushback(struct udap_xi_list *l, struct udap_xi *xi)
{
  l->list.emplace_back();
  udap_xi_copy(&l->list.back(), xi);
}

void
udap_xi_copy(struct udap_xi *dst, struct udap_xi *src)
{
  memcpy(dst, src, sizeof(struct udap_xi));
}

static bool
udap_xi_list_decode_item(struct list_reader *r, bool more)
{
  if(!more)
    return true;

  udap_xi_list *l = static_cast< udap_xi_list * >(r->user);
  l->list.emplace_back();
  return udap_xi_bdecode(&l->list.back(), r->buffer);
}

void
udap_xi_list_copy(struct udap_xi_list *dst, struct udap_xi_list *src)
{
  dst->list.clear();
  for(auto &itr : src->list)
    dst->list.emplace_back(itr);
}

bool
udap_xi_list_bdecode(struct udap_xi_list *l, udap_buffer_t *buff)
{
  list_reader r = {buff, l, &udap_xi_list_decode_item};
  return bencode_read_list(buff, &r);
}
}
