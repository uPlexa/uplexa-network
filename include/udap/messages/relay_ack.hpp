#ifndef UDAP_MESSAGES_RELAY_ACK_HPP
#define UDAP_MESSAGES_RELAY_ACK_HPP
#include <udap/crypto.hpp>
#include <udap/encrypted_frame.hpp>
#include <udap/link_message.hpp>
#include <udap/path_types.hpp>

namespace udap
{
  struct LR_AckRecord
  {
    uint64_t version = 0;

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    BDecode(udap_buffer_t* buf);
  };

  struct LR_AckMessage : public ILinkMessage
  {
    std::vector< EncryptedFrame > replies;
    uint64_t version = 0;

    LR_AckMessage(const RouterID& from);

    ~LR_AckMessage();

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    HandleMessage(udap_router* router) const;
  };
}  // namespace udap

#endif
