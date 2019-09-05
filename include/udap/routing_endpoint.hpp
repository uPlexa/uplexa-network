#ifndef UDAP_ROUTING_ENDPOINT_HPP
#define UDAP_ROUTING_ENDPOINT_HPP

#include <udap/buffer.h>
#include <udap/aligned.hpp>

namespace udap
{
  typedef AlignedBuffer< 32 > RoutingEndpoint_t;

  /// Interface for end to end crypto between endpoints
  struct IRoutingEndpoint
  {
    virtual ~IRoutingEndpoint(){};
  };
}

#endif