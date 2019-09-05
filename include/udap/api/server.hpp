#ifndef UDAP_API_SERVER_HPP
#define UDAP_API_SERVER_HPP

#include <udap/ev.h>
#include <udap/router.h>
#include <string>

namespace udap
{
  namespace api
  {
    struct ServerPImpl;

    struct Server
    {
      Server(udap_router* r);
      ~Server();

      bool
      Bind(const std::string& url, udap_ev_loop* loop);

     private:
      ServerPImpl* m_Impl;
    };

  }  // namespace api
}  // namespace udap

#endif