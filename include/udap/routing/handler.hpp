#ifndef UDAP_ROUTING_HANDLER_HPP
#define UDAP_ROUTING_HANDLER_HPP

#include <udap/buffer.h>
#include <udap/router.h>
#include <udap/dht.hpp>
#include <udap/messages/path_confirm.hpp>
#include <udap/messages/path_latency.hpp>
#include <udap/messages/path_transfer.hpp>

namespace udap
{
  namespace routing
  {
    // handles messages on the routing level
    struct IMessageHandler
    {
      virtual bool
      HandlePathTransferMessage(const PathTransferMessage* msg,
                                udap_router* r) = 0;

      virtual bool
      HandleHiddenServiceData(udap_buffer_t buf, udap_router* r) = 0;

      virtual bool
      HandlePathConfirmMessage(const PathConfirmMessage* msg,
                               udap_router* r) = 0;

      virtual bool
      HandlePathLatencyMessage(const PathLatencyMessage* msg,
                               udap_router* r) = 0;

      virtual bool

      HandleDHTMessage(const udap::dht::IMessage* msg, udap_router* r) = 0;
    };
  }  // namespace routing
}  // namespace udap

#endif