#ifndef UDAP_SERVICE_HPP
#define UDAP_SERVICE_HPP
#include <udap/aligned.hpp>
#include <udap/bencode.hpp>
#include <udap/crypto.hpp>

namespace udap
{
  namespace service
  {
    /// hidden service address
    typedef udap::AlignedBuffer< 32 > Address;

    typedef udap::AlignedBuffer< 16 > VanityNonce;

    struct Info : public udap::IBEncodeMessage
    {
      udap::PubKey enckey;
      udap::PubKey signkey;
      uint64_t version = 0;
      VanityNonce vanity;

      /// calculate our address
      void
      CalculateAddress(udap_crypto* c, Address& addr) const;

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* buf);
    };

    // private keys
    struct Identity : public udap::IBEncodeMessage
    {
      udap::SecretKey enckey;
      udap::SecretKey signkey;
      uint64_t version = 0;
      VanityNonce vanity;

      // public service info
      Info pub;

      // regenerate secret keys
      void
      RegenerateKeys(udap_crypto* c);

      // load from file
      bool
      LoadFromFile(const std::string& fpath);
    };

  };  // namespace service
}  // namespace udap

#endif