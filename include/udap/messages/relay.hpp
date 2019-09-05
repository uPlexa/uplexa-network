#ifndef UDAP_MESSAGES_RELAY_HPP
#define UDAP_MESSAGES_RELAY_HPP
#include <udap/link_message.hpp>

#include <udap/crypto.hpp>
#include <udap/encrypted.hpp>
#include <udap/path_types.hpp>
#include <vector>

namespace udap
{
  struct RelayUpstreamMessage : public ILinkMessage
  {
    PathID_t pathid;
    Encrypted X;
    TunnelNonce Y;

    RelayUpstreamMessage();
    RelayUpstreamMessage(const RouterID& from);
    ~RelayUpstreamMessage();

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    HandleMessage(udap_router* router) const;
  };

  struct RelayDownstreamMessage : public ILinkMessage
  {
    PathID_t pathid;
    Encrypted X;
    TunnelNonce Y;
    RelayDownstreamMessage();
    RelayDownstreamMessage(const RouterID& from);
    ~RelayDownstreamMessage();

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    HandleMessage(udap_router* router) const;
  };
}  // namespace udap

#endif
