#ifndef UDAP_MESSAGES_LINK_INTRO_HPP
#define UDAP_MESSAGES_LINK_INTRO_HPP
#include <udap/link_message.hpp>
namespace udap
{
  struct LinkIntroMessage : public ILinkMessage
  {
    LinkIntroMessage(udap_rc* rc) : ILinkMessage(), RC(rc)
    {
    }

    ~LinkIntroMessage();

    udap_rc* RC;

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t* buf);

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    HandleMessage(udap_router* router) const;
  };
}

#endif
