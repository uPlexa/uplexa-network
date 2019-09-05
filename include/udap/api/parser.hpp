#ifndef UDAP_API_PARSER_HPP
#define UDAP_API_PARSER_HPP
#include <udap/bencode.h>
#include <udap/api/messages.hpp>

namespace udap
{
  namespace api
  {
    struct MessageParser
    {
      MessageParser();

      IMessage *
      ParseMessage(udap_buffer_t buf);

     private:
      static bool
      OnKey(dict_reader *r, udap_buffer_t *key);
      IMessage *msg = nullptr;
      dict_reader r;
    };
  }  // namespace api
}  // namespace udap

#endif