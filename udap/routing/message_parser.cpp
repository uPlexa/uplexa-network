#include <udap/messages/path_confirm.hpp>
#include <udap/messages/path_latency.hpp>
#include <udap/routing/message.hpp>

namespace udap
{
  namespace routing
  {
    InboundMessageParser::InboundMessageParser()
    {
      reader.user   = this;
      reader.on_key = &OnKey;
      firstKey      = false;
    }

    bool
    InboundMessageParser::OnKey(dict_reader* r, udap_buffer_t* key)
    {
      InboundMessageParser* self =
          static_cast< InboundMessageParser* >(r->user);

      if(key == nullptr && self->firstKey)
      {
        // empty dict
        return false;
      }
      if(!key)
        return true;
      if(self->firstKey)
      {
        udap_buffer_t strbuf;
        if(!udap_buffer_eq(*key, "A"))
          return false;
        if(!bencode_read_string(r->buffer, &strbuf))
          return false;
        if(strbuf.sz != 1)
          return false;
        switch(*strbuf.cur)
        {
          case 'L':
            self->msg = new PathLatencyMessage;
            break;
          case 'P':
            self->msg = new PathConfirmMessage;
            break;
          default:
            udap::Error("invalid routing message id: ", *strbuf.cur);
        }
        self->firstKey = false;
        return self->msg != nullptr;
      }
      else
      {
        return self->msg->DecodeKey(*key, r->buffer);
      }
    }

    bool
    InboundMessageParser::ParseMessageBuffer(udap_buffer_t buf,
                                             IMessageHandler* h,
                                             udap_router* r)
    {
      bool result = false;
      msg         = nullptr;
      firstKey    = true;
      if(bencode_read_dict(&buf, &reader))
      {
        result = msg->HandleMessage(h, r);
        delete msg;
      }
      else
        udap::Error("read dict failed");
      return result;
    }
  }  // namespace routing
}  // namespace udap