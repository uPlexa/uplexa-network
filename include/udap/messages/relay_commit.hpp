#ifndef UDAP_RELAY_COMMIT_HPP
#define UDAP_RELAY_COMMIT_HPP
#include <udap/crypto.hpp>
#include <udap/encrypted_ack.hpp>
#include <udap/encrypted_frame.hpp>
#include <udap/link_message.hpp>
#include <udap/path_types.hpp>
#include <udap/pow.hpp>
#include <vector>

namespace udap
{
  // forward declare
  namespace path
  {
    struct PathContext;
  }

  struct LR_CommitRecord
  {
    PubKey commkey;
    RouterID nextHop;
    TunnelNonce tunnelNonce;
    PathID_t txid, rxid;

    PoW *work        = nullptr;
    uint64_t version = 0;

    bool
    BDecode(udap_buffer_t *buf);

    bool
    BEncode(udap_buffer_t *buf) const;

    ~LR_CommitRecord();

    bool
    operator==(const LR_CommitRecord &other) const;

   private:
    static bool
    OnKey(dict_reader *r, udap_buffer_t *buf);
  };

  struct LR_CommitMessage : public ILinkMessage
  {
    std::vector< EncryptedFrame > frames;
    uint64_t version;

    LR_CommitMessage() : ILinkMessage()
    {
    }

    LR_CommitMessage(const RouterID &from) : ILinkMessage(from)
    {
    }

    ~LR_CommitMessage();

    void
    Clear();

    bool
    DecodeKey(udap_buffer_t key, udap_buffer_t *buf);

    bool
    BEncode(udap_buffer_t *buf) const;

    bool
    HandleMessage(udap_router *router) const;

    bool
    AsyncDecrypt(udap::path::PathContext *context) const;
  };
}  // namespace udap

#endif
