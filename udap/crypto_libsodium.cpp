#include <assert.h>
#include <udap/crypto.h>
#include <sodium.h>
#include <udap/crypto.hpp>
#include "mem.hpp"

namespace udap
{
  namespace sodium
  {
    static bool
    xchacha20(udap_buffer_t buff, const byte_t *k, const byte_t *n)
    {
      return crypto_stream_xchacha20_xor(buff.base, buff.base, buff.sz, n, k)
          == 0;
    }

    static bool
    dh(uint8_t *out, uint8_t *client_pk, uint8_t *server_pk, uint8_t *themPub,
       uint8_t *usSec)
    {
      udap::SharedSecret shared;
      crypto_generichash_state h;
      const size_t outsz = SHAREDKEYSIZE;

      if(crypto_scalarmult_curve25519(shared, usSec, themPub))
        return false;
      crypto_generichash_init(&h, NULL, 0U, outsz);
      crypto_generichash_update(&h, client_pk, 32);
      crypto_generichash_update(&h, server_pk, 32);
      crypto_generichash_update(&h, shared, 32);
      crypto_generichash_final(&h, out, outsz);
      return true;
    }

    static bool
    dh_client(uint8_t *shared, uint8_t *pk, uint8_t *sk, uint8_t *n)
    {
      udap::SharedSecret dh_result;
      if(dh(dh_result, udap::seckey_topublic(sk), pk, pk, sk))
      {
        return crypto_generichash(shared, 32, n, 32, dh_result, 32) != -1;
      }
      return false;
    }

    static bool
    dh_server(uint8_t *shared, uint8_t *pk, uint8_t *sk, uint8_t *n)
    {
      udap::SharedSecret dh_result;
      if(dh(dh_result, pk, udap::seckey_topublic(sk), pk, sk))
      {
        return crypto_generichash(shared, 32, n, 32, dh_result, 32) != -1;
      }
      return false;
    }

    static bool
    hash(uint8_t *result, udap_buffer_t buff)
    {
      return crypto_generichash(result, HASHSIZE, buff.base, buff.sz, nullptr,
                                0)
          != -1;
    }

    static bool
    shorthash(uint8_t *result, udap_buffer_t buff)
    {
      return crypto_generichash(result, SHORTHASHSIZE, buff.base, buff.sz,
                                nullptr, 0)
          != -1;
    }

    static bool
    hmac(uint8_t *result, udap_buffer_t buff, const uint8_t *secret)
    {
      return crypto_generichash(result, HMACSIZE, buff.base, buff.sz, secret,
                                HMACSECSIZE)
          != -1;
    }

    static bool
    sign(uint8_t *result, const uint8_t *secret, udap_buffer_t buff)
    {
      return crypto_sign_detached(result, nullptr, buff.base, buff.sz, secret)
          != -1;
    }

    static bool
    verify(const uint8_t *pub, udap_buffer_t buff, const uint8_t *sig)
    {
      return crypto_sign_verify_detached(sig, buff.base, buff.sz, pub) != -1;
    }

    static void
    randomize(udap_buffer_t buff)
    {
      randombytes((unsigned char *)buff.base, buff.sz);
    }

    static inline void
    randbytes(void *ptr, size_t sz)
    {
      randombytes((unsigned char *)ptr, sz);
    }

    static void
    sigkeygen(uint8_t *keys)
    {
      crypto_sign_keypair(keys + 32, keys);
    }

    static void
    enckeygen(uint8_t *keys)
    {
      crypto_box_keypair(keys + 32, keys);
    }
  }  // namespace sodium

  const byte_t *
  seckey_topublic(const byte_t *sec)
  {
    return sec + 32;
  }

  byte_t *
  seckey_topublic(byte_t *sec)
  {
    return sec + 32;
  }

}  // namespace udap

extern "C" {
const byte_t *
udap_seckey_topublic(const byte_t *secret)
{
  return secret + 32;
}

void
udap_crypto_libsodium_init(struct udap_crypto *c)
{
  assert(sodium_init() != -1);
  c->xchacha20           = udap::sodium::xchacha20;
  c->dh_client           = udap::sodium::dh_client;
  c->dh_server           = udap::sodium::dh_server;
  c->transport_dh_client = udap::sodium::dh_client;
  c->transport_dh_server = udap::sodium::dh_server;
  c->hash                = udap::sodium::hash;
  c->shorthash           = udap::sodium::shorthash;
  c->hmac                = udap::sodium::hmac;
  c->sign                = udap::sodium::sign;
  c->verify              = udap::sodium::verify;
  c->randomize           = udap::sodium::randomize;
  c->randbytes           = udap::sodium::randbytes;
  c->identity_keygen     = udap::sodium::sigkeygen;
  c->encryption_keygen   = udap::sodium::enckeygen;
  int seed;
  c->randbytes(&seed, sizeof(seed));
  srand(seed);
}
}
