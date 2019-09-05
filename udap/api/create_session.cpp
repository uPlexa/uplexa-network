#include <list>
#include <udap/api/messages.hpp>
#include <udap/encrypted.hpp>
#include <string>

namespace udap
{
  namespace api
  {
    bool
    CreateSessionMessage::DecodeParams(udap_buffer_t *buf)
    {
      std::list< udap::Encrypted > params;
      return BEncodeReadList(params, buf);
    }
  }  // namespace api
}  // namespace udap