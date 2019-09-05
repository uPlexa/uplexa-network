#ifndef UDAP_ENDPOINT_HANDLER_HPP
#define UDAP_ENDPOINT_HANDLER_HPP

#include <udap/buffer.h>

namespace udap
{
  // hidden service endpoint handler
  struct IEndpointHandler
  {
    ~IEndpointHandler(){};

    virtual void
    HandleMessage(udap_buffer_t buf) = 0;
  };
}  // namespace udap

#endif