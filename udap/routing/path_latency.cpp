#include <udap/messages/path_latency.hpp>
#include <udap/routing/handler.hpp>

namespace udap
{
  namespace routing
  {
    PathLatencyMessage::PathLatencyMessage()
    {
    }

    bool
    PathLatencyMessage::DecodeKey(udap_buffer_t key, udap_buffer_t* val)
    {
      bool read = false;
      if(!BEncodeMaybeReadDictInt("L", L, read, key, val))
        return false;
      if(!BEncodeMaybeReadDictInt("T", T, read, key, val))
        return false;
      return read;
    }

    bool
    PathLatencyMessage::BEncode(udap_buffer_t* buf) const
    {
      if(!bencode_start_dict(buf))
        return false;
      if(!BEncodeWriteDictMsgType(buf, "A", "L"))
        return false;
      if(L)
      {
        if(!BEncodeWriteDictInt(buf, "L", L))
          return false;
      }
      if(T)
      {
        if(!BEncodeWriteDictInt(buf, "T", T))
          return false;
      }
      return bencode_end(buf);
    }

    bool
    PathLatencyMessage::HandleMessage(IMessageHandler* h, udap_router* r) const
    {
      return h && h->HandlePathLatencyMessage(this, r);
    }

  }  // namespace routing
}  // namespace udap