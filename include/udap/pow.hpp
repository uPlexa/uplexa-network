#ifndef UDAP_POW_HPP
#define UDAP_POW_HPP
#include <udap/buffer.h>
#include <udap/crypto.h>
#include <udap/router_id.hpp>

namespace udap
{
  /// proof of work
  struct PoW
  {
    static constexpr size_t MaxSize = 128;

    RouterID router;
    uint64_t version          = 0;
    uint32_t extendedLifetime = 0;
    AlignedBuffer< 32 > nonce;

    bool
    BEncode(udap_buffer_t* buf) const;

    bool
    BDecode(udap_buffer_t* buf);

    bool
    IsValid(udap_shorthash_func hashfunc, const RouterID& us) const;

    bool
    operator==(const PoW& other) const
    {
      return router == other.router && version == other.version
          && extendedLifetime == other.extendedLifetime && nonce == other.nonce;
    }

    bool
    operator!=(const PoW& other) const
    {
      return !(*this == other);
    }
  };
}  // namespace udap

#endif