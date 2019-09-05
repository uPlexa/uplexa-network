#include <udap/time.h>
#include <udap/bencode.hpp>
#include <udap/messages/path_confirm.hpp>
#include <udap/routing/handler.hpp>

namespace udap
{
  namespace routing
  {
    PathConfirmMessage::PathConfirmMessage() : pathLifetime(0), pathCreated(0)
    {
    }

    PathConfirmMessage::PathConfirmMessage(uint64_t lifetime)
        : pathLifetime(lifetime), pathCreated(udap_time_now_ms())
    {
    }

    bool
    PathConfirmMessage::DecodeKey(udap_buffer_t key, udap_buffer_t* val)
    {
      bool read = false;
      if(!BEncodeMaybeReadDictInt("L", pathLifetime, read, key, val))
        return false;
      if(!BEncodeMaybeReadDictInt("S", pathCreated, read, key, val))
        return false;
      return read;
    }

    bool
    PathConfirmMessage::BEncode(udap_buffer_t* buf) const
    {
      if(!bencode_start_dict(buf))
        return false;
      if(!BEncodeWriteDictMsgType(buf, "A", "P"))
        return false;
      if(!BEncodeWriteDictInt(buf, "L", pathLifetime))
        return false;
      if(!BEncodeWriteDictInt(buf, "S", pathCreated))
        return false;
      return bencode_end(buf);
    }

    bool
    PathConfirmMessage::HandleMessage(IMessageHandler* h, udap_router* r) const
    {
      return h && h->HandlePathConfirmMessage(this, r);
    }

  }  // namespace routing
}  // namespace udap