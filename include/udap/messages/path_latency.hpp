#ifndef UDAP_MESSAGES_PATH_LATENCY_HPP
#define UDAP_MESSAGES_PATH_LATENCY_HPP

#include <udap/routing/message.hpp>

namespace udap
{
  namespace routing
  {
    struct PathLatencyMessage : public IMessage
    {
      uint64_t T = 0;
      uint64_t L = 0;
      PathLatencyMessage();

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* val);

      bool
      HandleMessage(IMessageHandler* h, udap_router* r) const;
    };
  }  // namespace routing
}  // namespace udap

#endif