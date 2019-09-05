#ifndef UDAP_API_CLIENT_HPP
#define UDAP_API_CLIENT_HPP

#include <string>

namespace udap
{
  namespace api
  {
    struct ClientPImpl;

    struct Client
    {
      Client();
      ~Client();

      bool
      Start(const std::string& apiURL);

      int
      Mainloop();

     private:
      ClientPImpl* m_Impl;
    };

  }  // namespace api
}  // namespace udap
#endif