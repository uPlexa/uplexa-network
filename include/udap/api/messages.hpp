#ifndef UDAP_API_MESSAGES_HPP
#define UDAP_API_MESSAGES_HPP

#include <list>
#include <udap/aligned.hpp>
#include <udap/bencode.hpp>
#include <udap/crypto.hpp>

namespace udap
{
  namespace api
  {
    // forward declare
    struct Client;
    struct Server;

    /// base message
    struct IMessage : public IBEncodeMessage
    {
      uint64_t sessionID = 0;
      uint64_t msgID     = 0;
      uint64_t version   = 0;
      udap::ShortHash hash;

      // the function name this message belongs to
      virtual std::string
      FunctionName() const = 0;

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

      virtual std::list< IBEncodeMessage* >
      GetParams() const = 0;

      virtual bool
      DecodeParams(udap_buffer_t* buf) = 0;

      bool
      IsWellFormed(udap_crypto* c, const std::string& password);

      void
      CalculateHash(udap_crypto* c, const std::string& password);
    };

    /// a "yes we got your command" type message
    struct AcknoledgeMessage : public IMessage
    {
    };

    /// start a session with the router
    struct CreateSessionMessage : public IMessage
    {
      std::list< IBEncodeMessage* >
      GetParams() const
      {
        return {};
      }

      bool
      DecodeParams(udap_buffer_t* buf);

      std::string
      FunctionName() const
      {
        return "CreateSession";
      }
    };

    /// a keepalive ping
    struct SessionPingMessage : public IMessage
    {
    };

    /// end a session with the router
    struct DestroySessionMessage : public IMessage
    {
    };

    /// base messgae type for hidden service control and transmission
    struct HSMessage : public IMessage
    {
      udap::PubKey pubkey;
      udap::Signature sig;

      /// validate signature on message (server side)
      bool
      SignatureIsValid(udap_crypto* crypto) const;

      /// sign message using secret key (client side)
      bool
      SignMessge(udap_crypto* crypto, byte_t* seckey);
    };

    /// create a new hidden service
    struct CreateServiceMessgae : public HSMessage
    {
    };

    /// end an already created hidden service we created
    struct DestroyServiceMessage : public HSMessage
    {
    };

    /// start lookup of another service's descriptor
    struct LookupServiceMessage : public IMessage
    {
    };

    /// publish our hidden service's descriptor
    struct PublishServiceMessage : public IMessage
    {
    };

    /// send pre encrypted data down a path we own
    struct SendPathDataMessage : public IMessage
    {
    };

  }  // namespace api
}  // namespace udap

#endif