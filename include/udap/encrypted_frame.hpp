#ifndef UDAP_ENCRYPTED_FRAME_HPP
#define UDAP_ENCRYPTED_FRAME_HPP

#include <udap/crypto.h>
#include <udap/mem.h>
#include <udap/threadpool.h>
#include <udap/encrypted.hpp>

namespace udap
{
  struct EncryptedFrame : public Encrypted
  {
    static constexpr size_t OverheadSize =
        PUBKEYSIZE + TUNNONCESIZE + SHORTHASHSIZE;

    EncryptedFrame() : EncryptedFrame(256)
    {
    }

    EncryptedFrame(const EncryptedFrame& other)
        : EncryptedFrame(other._data, other._sz)
    {
    }

    EncryptedFrame(byte_t* buf, size_t sz) : Encrypted(buf, sz)
    {
    }
    EncryptedFrame(size_t sz)
        : Encrypted(sz + PUBKEYSIZE + TUNNONCESIZE + SHORTHASHSIZE)
    {
    }

    EncryptedFrame&
    operator=(const EncryptedFrame& other)
    {
      if(_data)
        delete[] _data;
      _sz   = other._sz;
      _data = new byte_t[_sz];
      memcpy(_data, other._data, _sz);
      return *this;
    }

    bool
    DecryptInPlace(byte_t* seckey, udap_crypto* crypto);

    bool
    EncryptInPlace(byte_t* seckey, byte_t* other, udap_crypto* crypto);
  };

  /// TOOD: can only handle 1 frame at a time
  template < typename User >
  struct AsyncFrameEncrypter
  {
    typedef void (*EncryptHandler)(EncryptedFrame*, User*);

    static void
    Encrypt(void* user)
    {
      AsyncFrameEncrypter< User >* ctx =
          static_cast< AsyncFrameEncrypter< User >* >(user);

      if(ctx->frame->EncryptInPlace(ctx->seckey, ctx->otherKey, ctx->crypto))
        ctx->handler(ctx->frame, ctx->user);
      else
      {
        ctx->handler(nullptr, ctx->user);
      }
    }

    udap_crypto* crypto;
    byte_t* secretkey;
    EncryptHandler handler;
    EncryptedFrame* frame;
    User* user;
    byte_t* otherKey;

    AsyncFrameEncrypter(udap_crypto* c, byte_t* seckey, EncryptHandler h)
        : crypto(c), secretkey(seckey), handler(h)
    {
    }

    void
    AsyncEncrypt(udap_threadpool* worker, udap_buffer_t buf, byte_t* other,
                 User* u)
    {
      // TODO: should we own otherKey?
      otherKey = other;
      frame    = new EncryptedFrame(buf.sz);
      memcpy(frame->data() + PUBKEYSIZE + TUNNONCESIZE + SHORTHASHSIZE,
             buf.base, buf.sz);
      user = u;
      udap_threadpool_queue_job(worker, {this, &Encrypt});
    }
  };

  /// TOOD: can only handle 1 frame at a time
  template < typename User >
  struct AsyncFrameDecrypter
  {
    typedef void (*DecryptHandler)(udap_buffer_t*, User*);

    static void
    Decrypt(void* user)
    {
      AsyncFrameDecrypter< User >* ctx =
          static_cast< AsyncFrameDecrypter< User >* >(user);

      if(ctx->target->DecryptInPlace(ctx->seckey, ctx->crypto))
      {
        auto buf = ctx->target->Buffer();
        buf->cur = buf->base + EncryptedFrame::OverheadSize;
        ctx->result(buf, ctx->context);
      }
      else
        ctx->result(nullptr, ctx->context);
    }

    AsyncFrameDecrypter(udap_crypto* c, byte_t* secretkey, DecryptHandler h)
        : result(h), crypto(c), seckey(secretkey)
    {
    }

    DecryptHandler result;
    User* context;
    udap_crypto* crypto;
    byte_t* seckey;
    EncryptedFrame* target;

    void
    AsyncDecrypt(udap_threadpool* worker, EncryptedFrame* frame, User* user)
    {
      target  = frame;
      context = user;
      udap_threadpool_queue_job(worker, {this, &Decrypt});
    }
  };
}  // namespace udap

#endif
