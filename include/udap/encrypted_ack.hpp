#ifndef UDAP_ENCRYPTED_ACK_HPP
#define UDAP_ENCRYPTED_ACK_HPP
#include <udap/encrypted.hpp>
namespace udap
{
  struct EncryptedAck : public Encrypted
  {
    bool
    DecryptInPlace(const byte_t* symkey, const byte_t* nonce,
                   udap_crypto* crypto);
  };
}

#endif