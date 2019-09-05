#include "config.hpp"
#include <udap/config.h>
#include "ini.hpp"
#include "mem.hpp"

namespace udap
{
  template < typename Config, typename Section >
  static const Section &
  find_section(Config &c, const std::string &name, const Section &fallback)
  {
    if(c.sections.find(name) == c.sections.end())
      return fallback;
    return c.sections[name].values;
  }

  bool
  Config::Load(const char *fname)
  {
    std::ifstream f;
    f.open(fname);
    if(f.is_open())
    {
      ini::Parser parser(f);
      auto &top = parser.top();
      router    = find_section(top, "router", section_t{});
      network   = find_section(top, "network", section_t{});
      connect   = find_section(top, "connect", section_t{});
      netdb     = find_section(top, "netdb", section_t{});
      iwp_links = find_section(top, "bind", section_t{});
      return true;
    }
    return false;
  };

}  // namespace udap

extern "C" {

void
udap_new_config(struct udap_config **conf)
{
  udap_config *c = new udap_config;
  *conf           = c;
}

void
udap_free_config(struct udap_config **conf)
{
  if(*conf)
    delete *conf;
  *conf = nullptr;
}

int
udap_load_config(struct udap_config *conf, const char *fname)
{
  if(!conf->impl.Load(fname))
    return -1;
  return 0;
}

void
udap_config_iter(struct udap_config *conf, struct udap_config_iterator *iter)
{
  iter->conf                                                   = conf;
  std::map< std::string, udap::Config::section_t & > sections = {
      {"network", conf->impl.network},
      {"connect", conf->impl.connect},
      {"bind", conf->impl.iwp_links},
      {"netdb", conf->impl.netdb}};

  for(const auto item : conf->impl.router)
    iter->visit(iter, "router", item.first.c_str(), item.second.c_str());

  for(const auto section : sections)
    for(const auto item : section.second)
      iter->visit(iter, section.first.c_str(), item.first.c_str(),
                  item.second.c_str());
}
}
