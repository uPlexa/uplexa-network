#include "logger.hpp"

namespace udap
{
  Logger _glog;

  void
  SetLogLevel(LogLevel lvl)
  {
    _glog.minlevel = lvl;
  }
}
