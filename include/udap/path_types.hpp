#ifndef UDAP_PATH_TYPES_HPP
#define UDAP_PATH_TYPES_HPP

#include <udap/crypto.h>
#include <udap/aligned.hpp>

namespace udap
{
  typedef AlignedBuffer< PATHIDSIZE > PathID_t;
}

#endif