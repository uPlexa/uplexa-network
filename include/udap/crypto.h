#ifndef UDAP_CRYPTO_H_
#define UDAP_CRYPTO_H_
#include <udap/buffer.h>
#include <udap/common.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * crypto.h
 *
 * libsodium abstraction layer
 * potentially allow libssl support in the future
 */

#ifdef __cplusplus
extern "C" {
#endif

#define PUBKEYSIZE 32
#define SECKEYSIZE 64
#define NONCESIZE 24
#define SHAREDKEYSIZE 32
#define HASHSIZE 64
#define SHORTHASHSIZE 32
#define HMACSECSIZE 32
#define SIGSIZE 64
#define TUNNONCESIZE 32
#define HMACSIZE 32
#define PATHIDSIZE 16

/*
typedef byte_t udap_pubkey_t[PUBKEYSIZE];
typedef byte_t udap_seckey_t[SECKEYSIZE];
typedef byte_t udap_nonce_t[NONCESIZE];
typedef byte_t udap_sharedkey_t[SHAREDKEYSIZE];
typedef byte_t udap_hash_t[HASHSIZE];
typedef byte_t udap_shorthash_t[SHORTHASHSIZE];
typedef byte_t udap_hmac_t[HMACSIZE];
typedef byte_t udap_hmacsec_t[HMACSECSIZE];
typedef byte_t udap_sig_t[SIGSIZE];
typedef byte_t udap_tunnel_nonce_t[TUNNONCESIZE];
*/

/// label functors

/// PKE(result, publickey, secretkey, nonce)
typedef bool (*udap_path_dh_func)(byte_t *, byte_t *, byte_t *, byte_t *);

/// TKE(result, publickey, secretkey, nonce)
typedef bool (*udap_transport_dh_func)(byte_t *, byte_t *, byte_t *, byte_t *);

/// SD/SE(buffer, key, nonce)
typedef bool (*udap_sym_cipher_func)(udap_buffer_t, const byte_t *,
                                      const byte_t *);

/// H(result, body)
typedef bool (*udap_hash_func)(byte_t *, udap_buffer_t);

/// SH(result, body)
typedef bool (*udap_shorthash_func)(byte_t *, udap_buffer_t);

/// MDS(result, body, shared_secret)
typedef bool (*udap_hmac_func)(byte_t *, udap_buffer_t, const byte_t *);

/// S(sig, secretkey, body)
typedef bool (*udap_sign_func)(byte_t *, const byte_t *, udap_buffer_t);

/// V(sig, body, secretkey)
typedef bool (*udap_verify_func)(const byte_t *, udap_buffer_t,
                                  const byte_t *);

/// library crypto configuration
struct udap_crypto
{
  /// xchacha symettric cipher
  udap_sym_cipher_func xchacha20;
  /// path dh creator's side
  udap_path_dh_func dh_client;
  /// path dh relay side
  udap_path_dh_func dh_server;
  /// transport dh client side
  udap_transport_dh_func transport_dh_client;
  /// transport dh server side
  udap_transport_dh_func transport_dh_server;
  /// blake2b 512 bit
  udap_hash_func hash;
  /// blake2b 256 bit
  udap_shorthash_func shorthash;
  /// blake2s 256 bit hmac
  udap_hmac_func hmac;
  /// ed25519 sign
  udap_sign_func sign;
  /// ed25519 verify
  udap_verify_func verify;
  /// randomize buffer
  void (*randomize)(udap_buffer_t);
  /// randomizer memory
  void (*randbytes)(void *, size_t);
  /// generate signing keypair
  void (*identity_keygen)(byte_t *);
  /// generate encryption keypair
  void (*encryption_keygen)(byte_t *);
};

/// set crypto function pointers to use libsodium
void
udap_crypto_libsodium_init(struct udap_crypto *c);

/// check for initialize crypto
bool
udap_crypto_initialized(struct udap_crypto *c);

#ifdef __cplusplus
}
#endif

#endif
