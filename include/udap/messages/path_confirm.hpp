#ifndef UDAP_MESSAGE_PATH_CONFIRM_HPP
#define UDAP_MESSAGE_PATH_CONFIRM_HPP

#include <udap/routing/message.hpp>

namespace udap
{
  namespace routing
  {
    struct PathConfirmMessage : public IMessage
    {
      uint64_t pathLifetime;
      uint64_t pathCreated;
      PathConfirmMessage();
      PathConfirmMessage(uint64_t lifetime);
      ~PathConfirmMessage(){};

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* val);

      bool
      BDecode(udap_buffer_t* buf);

      bool
      HandleMessage(IMessageHandler* h, udap_router* r) const;
    };
  }  // namespace routing
}  // namespace udap

#endif