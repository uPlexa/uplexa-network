#ifndef LIBUDAP_CONFIG_HPP
#define LIBUDAP_CONFIG_HPP
#include <list>
#include <string>

#include <udap/config.h>

namespace udap
{
  struct Config
  {
    typedef std::list< std::pair< std::string, std::string > > section_t;

    section_t router;
    section_t network;
    section_t netdb;
    section_t iwp_links;
    section_t connect;

    bool
    Load(const char *fname);
  };
}  // namespace udap

extern "C" {
struct udap_config
{
  udap::Config impl;
};
}

#endif
