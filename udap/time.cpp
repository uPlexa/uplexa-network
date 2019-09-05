#include <udap/time.h>
#include <chrono>

namespace udap
{
  typedef std::chrono::steady_clock clock_t;

  template < typename Res, typename IntType >
  static IntType
  time_since_epoch()
  {
    return std::chrono::duration_cast< Res >(
               udap::clock_t::now().time_since_epoch())
        .count();
  }
}  // namespace udap

extern "C" {
udap_time_t
udap_time_now_ms()
{
  return udap::time_since_epoch< std::chrono::milliseconds, udap_time_t >();
}

udap_seconds_t
udap_time_now_sec()
{
  return udap::time_since_epoch< std::chrono::seconds, udap_seconds_t >();
}
}
