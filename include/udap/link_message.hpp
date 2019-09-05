#ifndef UDAP_LINK_MESSAGE_HPP
#define UDAP_LINK_MESSAGE_HPP

#include <udap/link.h>
#include <udap/bencode.hpp>
#include <udap/router_id.hpp>

#include <queue>
#include <vector>

namespace udap
{
  struct ILinkMessage;

  typedef std::queue< ILinkMessage* > SendQueue;

  /// parsed link layer message
  struct ILinkMessage : public IBEncodeMessage
  {
    /// who did this message come from (rc.k)
    RouterID remote  = {};
    uint64_t version = 0;

    ILinkMessage() = default;
    ILinkMessage(const RouterID& id);

    virtual bool
    HandleMessage(udap_router* router) const = 0;
  };

  struct InboundMessageParser
  {
    InboundMessageParser(udap_router* router);
    dict_reader reader;

    static bool
    OnKey(dict_reader* r, udap_buffer_t* buf);

    /// start processig message from a link session
    bool
    ProcessFrom(udap_link_session* from, udap_buffer_t buf);

    /// called when the message is fully read
    /// return true when the message was accepted otherwise returns false
    bool
    MessageDone();

   private:
    RouterID
    GetCurrentFrom();

   private:
    bool firstkey;
    udap_router* router;
    udap_link_session* from;
    ILinkMessage* msg = nullptr;
  };
}  // namespace udap

#endif
