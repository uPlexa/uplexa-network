#include <udap/bencode.h>
#include <udap/router_contact.h>
#include <udap/messages/link_intro.hpp>
#include "logger.hpp"

namespace udap
{
  LinkIntroMessage::~LinkIntroMessage()
  {
  }

  bool
  LinkIntroMessage::DecodeKey(udap_buffer_t key, udap_buffer_t* buf)
  {
    if(udap_buffer_eq(key, "r"))
    {
      if(!udap_rc_bdecode(RC, buf))
      {
        udap::Warn("failed to decode RC");
        return false;
      }
      remote = (byte_t*)RC->pubkey;
      udap::Debug("decoded RC from ", remote);
      return true;
    }
    else if(udap_buffer_eq(key, "v"))
    {
      if(!bencode_read_integer(buf, &version))
        return false;
      if(version != UDAP_PROTO_VERSION)
      {
        udap::Warn("udap protocol version missmatch ", version,
                    " != ", UDAP_PROTO_VERSION);
        return false;
      }
      udap::Debug("LIM version ", version);
      return true;
    }
    else
    {
      udap::Warn("invalid LIM key: ", *key.cur);
      return false;
    }
  }

  bool
  LinkIntroMessage::BEncode(udap_buffer_t* buf) const
  {
    if(!bencode_start_dict(buf))
      return false;

    if(!bencode_write_bytestring(buf, "a", 1))
      return false;
    if(!bencode_write_bytestring(buf, "i", 1))
      return false;

    if(RC)
    {
      if(!bencode_write_bytestring(buf, "r", 1))
        return false;
      if(!udap_rc_bencode(RC, buf))
        return false;
    }

    if(!bencode_write_version_entry(buf))
      return false;

    return bencode_end(buf);
  }

  bool
  LinkIntroMessage::HandleMessage(udap_router* router) const
  {
    udap::Info("got LIM from ", remote);
    return true;
  }
}
