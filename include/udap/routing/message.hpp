#ifndef UDAP_ROUTING_MESSAGE_HPP
#define UDAP_ROUTING_MESSAGE_HPP

#include <udap/buffer.h>
#include <udap/router.h>
#include <udap/bencode.hpp>
#include <udap/path_types.hpp>

namespace udap
{
  namespace routing
  {
    struct IMessageHandler;

    struct IMessage : public udap::IBEncodeMessage
    {
      udap::PathID_t from;

      virtual bool
      HandleMessage(IMessageHandler* h, udap_router* r) const = 0;
    };

    struct InboundMessageParser
    {
      InboundMessageParser();
      bool
      ParseMessageBuffer(udap_buffer_t buf, IMessageHandler* handler,
                         udap_router* r);

     private:
      static bool
      OnKey(dict_reader* r, udap_buffer_t* key);
      bool firstKey;
      dict_reader reader;
      IMessage* msg;
    };
  }  // namespace routing
}  // namespace udap

#endif