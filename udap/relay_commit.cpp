#include <udap/bencode.hpp>
#include <udap/messages/path_confirm.hpp>
#include <udap/messages/relay_commit.hpp>
#include "buffer.hpp"
#include "logger.hpp"
#include "router.hpp"

namespace udap
{
  LR_CommitMessage::~LR_CommitMessage()
  {
  }

  bool
  LR_CommitMessage::DecodeKey(udap_buffer_t key, udap_buffer_t* buf)
  {
    if(udap_buffer_eq(key, "c"))
    {
      return BEncodeReadList(frames, buf);
    }
    bool read = false;
    if(!BEncodeMaybeReadVersion("v", version, UDAP_PROTO_VERSION, read, key,
                                buf))
      return false;

    return read;
  }

  bool
  LR_CommitMessage::BEncode(udap_buffer_t* buf) const
  {
    if(!bencode_start_dict(buf))
      return false;
    // msg type
    if(!BEncodeWriteDictMsgType(buf, "a", "c"))
      return false;
    // frames
    if(!BEncodeWriteDictList("c", frames, buf))
      return false;
    // version
    if(!bencode_write_version_entry(buf))
      return false;

    return bencode_end(buf);
  }

  bool
  LR_CommitMessage::HandleMessage(udap_router* router) const
  {
    if(frames.size() != MAXHOPS)
    {
      udap::Error("LRCM invalid number of records, ", frames.size(),
                   "!=", MAXHOPS);
      return false;
    }
    if(!router->paths.AllowingTransit())
    {
      udap::Error("got an LRCM from ", remote,
                   " when we are not allowing transit");
      return false;
    }
    udap::Info("Got LRCM from ", remote);
    return AsyncDecrypt(&router->paths);
  }

  bool
  LR_CommitRecord::BEncode(udap_buffer_t* buf) const
  {
    if(!bencode_start_dict(buf))
      return false;

    if(!BEncodeWriteDictEntry("c", commkey, buf))
      return false;
    if(!BEncodeWriteDictEntry("i", nextHop, buf))
      return false;
    if(!BEncodeWriteDictEntry("n", tunnelNonce, buf))
      return false;
    if(!BEncodeWriteDictEntry("r", rxid, buf))
      return false;
    if(!BEncodeWriteDictEntry("t", txid, buf))
      return false;
    if(!bencode_write_version_entry(buf))
      return false;
    if(work && !BEncodeWriteDictEntry("w", *work, buf))
      return false;

    return bencode_end(buf);
  }

  LR_CommitRecord::~LR_CommitRecord()
  {
    if(work)
      delete work;
  }

  bool
  LR_CommitRecord::OnKey(dict_reader* r, udap_buffer_t* key)
  {
    if(!key)
      return true;

    LR_CommitRecord* self = static_cast< LR_CommitRecord* >(r->user);

    bool read = false;

    if(!BEncodeMaybeReadDictEntry("c", self->commkey, read, *key, r->buffer))
      return false;
    if(!BEncodeMaybeReadDictEntry("i", self->nextHop, read, *key, r->buffer))
      return false;
    if(!BEncodeMaybeReadDictEntry("n", self->tunnelNonce, read, *key,
                                  r->buffer))
      return false;
    if(!BEncodeMaybeReadDictEntry("r", self->rxid, read, *key, r->buffer))
      return false;
    if(!BEncodeMaybeReadDictEntry("t", self->txid, read, *key, r->buffer))
      return false;
    if(!BEncodeMaybeReadVersion("v", self->version, UDAP_PROTO_VERSION, read,
                                *key, r->buffer))
      return false;
    if(udap_buffer_eq(*key, "w"))
    {
      // check for duplicate
      if(self->work)
      {
        udap::Warn("duplicate POW in LRCR");
        return false;
      }

      self->work = new PoW;
      return self->work->BDecode(r->buffer);
    }
    return read;
  }

  bool
  LR_CommitRecord::BDecode(udap_buffer_t* buf)
  {
    dict_reader r;
    r.user   = this;
    r.on_key = &OnKey;
    return bencode_read_dict(buf, &r);
  }

  bool
  LR_CommitRecord::operator==(const LR_CommitRecord& other) const
  {
    if(work && other.work)
    {
      if(*work != *other.work)
        return false;
    }
    return nextHop == other.nextHop && commkey == other.commkey
        && txid == other.txid && rxid == other.rxid;
  }

  struct LRCMFrameDecrypt
  {
    typedef udap::path::PathContext Context;
    typedef udap::path::TransitHop Hop;
    typedef AsyncFrameDecrypter< LRCMFrameDecrypt > Decrypter;
    Decrypter* decrypter;
    std::deque< EncryptedFrame > frames;
    Context* context;
    // decrypted record
    LR_CommitRecord record;
    // the actual hop
    Hop* hop;

    LRCMFrameDecrypt(Context* ctx, Decrypter* dec,
                     const LR_CommitMessage* commit)
        : decrypter(dec), context(ctx), hop(new Hop)
    {
      for(const auto& f : commit->frames)
        frames.push_back(f);
      hop->info.downstream = commit->remote;
    }

    ~LRCMFrameDecrypt()
    {
      delete decrypter;
    }

    /// this must be done from logic thread
    static void
    SendLRCM(void* user)
    {
      LRCMFrameDecrypt* self = static_cast< LRCMFrameDecrypt* >(user);
      self->context->ForwardLRCM(self->hop->info.upstream, self->frames);
      delete self;
    }

    static void
    SendPathConfirm(void* user)
    {
      LRCMFrameDecrypt* self = static_cast< LRCMFrameDecrypt* >(user);
      udap::routing::PathConfirmMessage confirm(self->hop->lifetime);
      if(!self->hop->SendRoutingMessage(&confirm, self->context->Router()))
      {
        udap::Error("failed to send path confirmation for ", self->hop->info);
      }
      delete self;
    }

    static void
    HandleDecrypted(udap_buffer_t* buf, LRCMFrameDecrypt* self)
    {
      auto& info = self->hop->info;
      if(!buf)
      {
        udap::Error("LRCM decrypt failed from ", info.downstream);
        delete self;
        return;
      }
      buf->cur = buf->base + EncryptedFrame::OverheadSize;
      udap::Debug("decrypted LRCM from ", info.downstream);
      // successful decrypt
      if(!self->record.BDecode(buf))
      {
        udap::Error("malformed frame inside LRCM from ", info.downstream);
        delete self;
        return;
      }

      info.txID     = self->record.txid;
      info.rxID     = self->record.rxid;
      info.upstream = self->record.nextHop;
      if(self->context->HasTransitHop(info))
      {
        udap::Error("duplicate transit hop ", info);
        delete self;
        return;
      }
      // generate path key as we are in a worker thread
      auto DH = self->context->Crypto()->dh_server;
      if(!DH(self->hop->pathKey, self->record.commkey,
             self->context->EncryptionSecretKey(), self->record.tunnelNonce))
      {
        udap::Error("LRCM DH Failed ", info);
        delete self;
        return;
      }
      if(self->record.work
         && self->record.work->IsValid(self->context->Crypto()->shorthash,
                                       self->context->OurRouterID()))
      {
        udap::Info("LRCM extended lifetime by ",
                    self->record.work->extendedLifetime, " seconds for ", info);
        self->hop->lifetime += 1000 * self->record.work->extendedLifetime;
      }

      // TODO: check if we really want to accept it
      self->hop->started = udap_time_now_ms();
      udap::Info("Accepted ", self->hop->info);
      self->context->PutTransitHop(self->hop);

      size_t sz = self->frames.front().size();
      // we pop the front element it was ours
      self->frames.pop_front();
      // put our response on the end
      self->frames.emplace_back(sz - EncryptedFrame::OverheadSize);
      // random junk for now
      self->frames.back().Randomize();

      if(self->context->HopIsUs(info.upstream))
      {
        // we are the farthest hop
        udap::Info("We are the farthest hop for ", info);
        // send a LRAM down the path
        udap_logic_queue_job(self->context->Logic(), {self, &SendPathConfirm});
      }
      else
      {
        // forward upstream
        // we are still in the worker thread so post job to logic
        udap_logic_queue_job(self->context->Logic(), {self, &SendLRCM});
      }
    }
  };

  bool
  LR_CommitMessage::AsyncDecrypt(udap::path::PathContext* context) const
  {
    LRCMFrameDecrypt::Decrypter* decrypter = new LRCMFrameDecrypt::Decrypter(
        context->Crypto(), context->EncryptionSecretKey(),
        &LRCMFrameDecrypt::HandleDecrypted);
    // copy frames so we own them
    LRCMFrameDecrypt* frames = new LRCMFrameDecrypt(context, decrypter, this);

    // decrypt frames async
    decrypter->AsyncDecrypt(context->Worker(), &frames->frames.front(), frames);
    return true;
  }
}  // namespace udap
