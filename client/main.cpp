#include <udap/api.hpp>

int
main(int argc, char* argv[])
{
  std::string url = udap::api::DefaultURL;
  if(argc > 1)
  {
    url = argv[1];
  }
  udap::api::Client cl;
  if(!cl.Start(url))
    return 1;
  return cl.Mainloop();
}