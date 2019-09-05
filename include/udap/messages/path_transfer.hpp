#ifndef UDAP_MESSAGES_PATH_TRANSFER_HPP
#define UDAP_MESSAGES_PATH_TRANSFER_HPP

#include <udap/crypto.hpp>
#include <udap/encrypted.hpp>
#include <udap/routing/message.hpp>

namespace udap
{
  namespace routing
  {
    struct PathTransferMessage : public IMessage
    {
      PathID_t P;
      Encrypted T;
      TunnelNonce Y;
    };

  }  // namespace routing
}  // namespace udap

#endif