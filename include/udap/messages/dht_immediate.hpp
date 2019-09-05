#ifndef UDAP_MESSAGES_DHT_IMMEDIATE_HPP
#define UDAP_MESSAGES_DHT_IMMEDIATE_HPP
#include <udap/dht.hpp>
#include <udap/link_message.hpp>
#include <vector>

namespace udap
{
  struct DHTImmeidateMessage : public ILinkMessage
  {
    DHTImmeidateMessage(const RouterID& from) : ILinkMessage(from)
    {
    }

    ~DHTImmeidateMessage();

    std::vector< udap::dht::IMessage* > msgs;

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    HandleMessage(udap_router* router) const;
  };
}

#endif
