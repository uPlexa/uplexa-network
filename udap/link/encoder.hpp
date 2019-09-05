#ifndef UDAP_LINK_ENCODER_HPP
#define UDAP_LINK_ENCODER_HPP

#include <udap/bencode.h>
#include <udap/buffer.h>
#include <udap/router_contact.h>

namespace udap
{
  /// encode Link Introduce Message onto a buffer
  /// if router is nullptr then the LIM's r member is omitted.
  bool
  EncodeLIM(udap_buffer_t* buff, udap_rc* router)
  {
    if(!bencode_start_dict(buff))
      return false;

    // message type
    if(!bencode_write_bytestring(buff, "a", 1))
      return false;
    if(!bencode_write_bytestring(buff, "i", 1))
      return false;

    // router contact
    if(router)
    {
      if(!bencode_write_bytestring(buff, "r", 1))
        return false;
      if(!udap_rc_bencode(router, buff))
        return false;
    }

    // version
    if(!bencode_write_version_entry(buff))
      return false;

    return bencode_end(buff);
  }
}

#endif
