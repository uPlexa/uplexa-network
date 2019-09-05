#include <udap/bencode.hpp>
#include <udap/dht.hpp>
#include <udap/messages/dht_immediate.hpp>
#include "router.hpp"
#include "router_contact.hpp"

#include <sodium.h>

#include <algorithm>  // std::find
#include <set>

namespace udap
{
  DHTImmeidateMessage::~DHTImmeidateMessage()
  {
    for(auto &msg : msgs)
      delete msg;
    msgs.clear();
  }

  bool
  DHTImmeidateMessage::DecodeKey(udap_buffer_t key, udap_buffer_t *buf)
  {
    if(udap_buffer_eq(key, "m"))
      return udap::dht::DecodeMesssageList(remote.data(), buf, msgs);
    if(udap_buffer_eq(key, "v"))
    {
      if(!bencode_read_integer(buf, &version))
        return false;
      return version == UDAP_PROTO_VERSION;
    }
    // bad key
    return false;
  }

  bool
  DHTImmeidateMessage::BEncode(udap_buffer_t *buf) const
  {
    if(!bencode_start_dict(buf))
      return false;

    // message type
    if(!bencode_write_bytestring(buf, "a", 1))
      return false;
    if(!bencode_write_bytestring(buf, "m", 1))
      return false;

    // dht messages
    if(!bencode_write_bytestring(buf, "m", 1))
      return false;
    // begin list
    if(!bencode_start_list(buf))
      return false;
    for(const auto &msg : msgs)
    {
      if(!msg->BEncode(buf))
        return false;
    }
    // end list
    if(!bencode_end(buf))
      return false;

    // protocol version
    if(!bencode_write_version_entry(buf))
      return false;

    return bencode_end(buf);
  }

  bool
  DHTImmeidateMessage::HandleMessage(udap_router *router) const
  {
    DHTImmeidateMessage *reply = new DHTImmeidateMessage(remote);
    bool result                = true;
    for(auto &msg : msgs)
    {
      result &= msg->HandleMessage(router, reply->msgs);
    }
    return result && router->SendToOrQueue(remote.data(), reply);
  }

  namespace dht
  {
    GotRouterMessage::~GotRouterMessage()
    {
      for(auto &rc : R)
        udap_rc_free(&rc);
      R.clear();
    }

    bool
    GotRouterMessage::BEncode(udap_buffer_t *buf) const
    {
      if(!bencode_start_dict(buf))
        return false;

      // message type
      if(!BEncodeWriteDictMsgType(buf, "A", "S"))
        return false;

      if(!BEncodeWriteDictList("R", R, buf))
        return false;

      // txid
      if(!BEncodeWriteDictInt(buf, "T", txid))
        return false;

      // version
      if(!BEncodeWriteDictInt(buf, "V", version))
        return false;

      return bencode_end(buf);
    }

    bool
    GotRouterMessage::DecodeKey(udap_buffer_t key, udap_buffer_t *val)
    {
      if(udap_buffer_eq(key, "R"))
      {
        return BEncodeReadList(R, val);
      }
      if(udap_buffer_eq(key, "T"))
      {
        return bencode_read_integer(val, &txid);
      }
      bool read = false;
      if(!BEncodeMaybeReadVersion("V", version, UDAP_PROTO_VERSION, read, key,
                                  val))
        return false;

      return read;
    }

    bool
    GotRouterMessage::HandleMessage(udap_router *router,
                                    std::vector< IMessage * > &replies) const
    {
      auto &dht    = router->dht->impl;
      auto pending = dht.FindPendingTX(From, txid);
      if(pending)
      {
        if(R.size())
        {
          pending->Completed(&R[0]);
          if(pending->requester != dht.OurKey())
          {
            replies.push_back(new GotRouterMessage(
                pending->target, pending->requesterTX, &R[0]));
          }
        }
        else
        {
          // iterate to next closest peer
          Key_t nextPeer;
          pending->exclude.insert(From);
          if(pending->exclude.size() < 3
             && dht.nodes->FindCloseExcluding(pending->target, nextPeer,
                                              pending->exclude))
          {
            udap::Info(pending->target, " was not found via ", From,
                        " iterating to next peer ", nextPeer, " already asked ",
                        pending->exclude.size(), " other peers");
            dht.LookupRouter(pending->target, pending->requester,
                             pending->requesterTX, nextPeer, nullptr, true,
                             pending->exclude);
          }
          else
          {
            udap::Info(pending->target, " was not found via ", From,
                        " and we won't look it up");
            pending->Completed(nullptr);
            if(pending->requester != dht.OurKey())
            {
              replies.push_back(new GotRouterMessage(
                  pending->target, pending->requesterTX, nullptr));
            }
          }
        }
        dht.RemovePendingLookup(From, txid);
        return true;
      }
      udap::Warn("Got response for DHT transaction we are not tracking, txid=",
                  txid);
      return false;
    }

    FindRouterMessage::~FindRouterMessage()
    {
    }

    bool
    FindRouterMessage::BEncode(udap_buffer_t *buf) const
    {
      if(!bencode_start_dict(buf))
        return false;

      // message type
      if(!bencode_write_bytestring(buf, "A", 1))
        return false;
      if(!bencode_write_bytestring(buf, "R", 1))
        return false;

      // iterative or not?
      if(!bencode_write_bytestring(buf, "I", 1))
        return false;
      if(!bencode_write_int(buf, iterative ? 1 : 0))
        return false;

      // key
      if(!bencode_write_bytestring(buf, "K", 1))
        return false;
      if(!bencode_write_bytestring(buf, K.data(), K.size()))
        return false;

      // txid
      if(!bencode_write_bytestring(buf, "T", 1))
        return false;
      if(!bencode_write_uint64(buf, txid))
        return false;

      // version
      if(!bencode_write_bytestring(buf, "V", 1))
        return false;
      if(!bencode_write_uint64(buf, version))
        return false;

      return bencode_end(buf);
    }

    bool
    FindRouterMessage::DecodeKey(udap_buffer_t key, udap_buffer_t *val)
    {
      udap_buffer_t strbuf;

      if(udap_buffer_eq(key, "I"))
      {
        uint64_t result;
        if(!bencode_read_integer(val, &result))
          return false;

        iterative = result != 0;
        return true;
      }
      if(udap_buffer_eq(key, "K"))
      {
        if(!bencode_read_string(val, &strbuf))
          return false;
        if(strbuf.sz != K.size())
          return false;

        memcpy(K.data(), strbuf.base, K.size());
        return true;
      }
      if(udap_buffer_eq(key, "T"))
      {
        return bencode_read_integer(val, &txid);
      }
      if(udap_buffer_eq(key, "V"))
      {
        return bencode_read_integer(val, &version);
      }
      return false;
    }

    bool
    FindRouterMessage::HandleMessage(udap_router *router,
                                     std::vector< IMessage * > &replies) const
    {
      auto &dht = router->dht->impl;
      if(!dht.allowTransit)
      {
        udap::Warn("Got DHT lookup from ", From,
                    " when we are not allowing dht transit");
        return false;
      }
      auto pending = dht.FindPendingTX(From, txid);
      if(pending)
      {
        udap::Warn("Got duplicate DHT lookup from ", From, " txid=", txid);
        return false;
      }
      dht.LookupRouterRelayed(From, txid, K, !iterative, replies);
      return true;
    }

    struct MessageDecoder
    {
      const Key_t &From;
      bool firstKey = true;
      IMessage *msg = nullptr;

      MessageDecoder(const Key_t &from) : From(from)
      {
      }

      static bool
      on_key(dict_reader *r, udap_buffer_t *key)
      {
        udap_buffer_t strbuf;
        MessageDecoder *dec = static_cast< MessageDecoder * >(r->user);
        // check for empty dict
        if(!key)
          return !dec->firstKey;

        // first key
        if(dec->firstKey)
        {
          if(!udap_buffer_eq(*key, "A"))
            return false;
          if(!bencode_read_string(r->buffer, &strbuf))
            return false;
          // bad msg size?
          if(strbuf.sz != 1)
            return false;
          switch(*strbuf.base)
          {
            case 'R':
              dec->msg = new FindRouterMessage(dec->From);
              break;
            case 'S':
              dec->msg = new GotRouterMessage(dec->From);
              break;
            default:
              udap::Warn("unknown dht message type: ", (char)*strbuf.base);
              // bad msg type
              return false;
          }
          dec->firstKey = false;
          return true;
        }
        else
          return dec->msg->DecodeKey(*key, r->buffer);
      }
    };

    IMessage *
    DecodeMesssage(const Key_t &from, udap_buffer_t *buf)
    {
      MessageDecoder dec(from);
      dict_reader r;
      r.user   = &dec;
      r.on_key = &MessageDecoder::on_key;
      if(bencode_read_dict(buf, &r))
        return dec.msg;
      else
      {
        if(dec.msg)
          delete dec.msg;
        return nullptr;
      }
    }

    struct ListDecoder
    {
      ListDecoder(const Key_t &from, std::vector< IMessage * > &list)
          : From(from), l(list){};

      const Key_t &From;
      std::vector< IMessage * > &l;

      static bool
      on_item(list_reader *r, bool has)
      {
        ListDecoder *dec = static_cast< ListDecoder * >(r->user);
        if(!has)
          return true;
        auto msg = DecodeMesssage(dec->From, r->buffer);
        if(msg)
        {
          dec->l.push_back(msg);
          return true;
        }
        else
          return false;
      }
    };

    bool
    DecodeMesssageList(const Key_t &from, udap_buffer_t *buf,
                       std::vector< IMessage * > &list)
    {
      ListDecoder dec(from, list);

      list_reader r;
      r.user    = &dec;
      r.on_item = &ListDecoder::on_item;
      return bencode_read_list(buf, &r);
    }

    SearchJob::SearchJob()
    {
      started = 0;
      requester.Zero();
      target.Zero();
    }

    SearchJob::SearchJob(const Key_t &asker, uint64_t tx, const Key_t &key,
                         udap_router_lookup_job *j,
                         const std::set< Key_t > &excludes)
        : job(j)
        , started(udap_time_now_ms())
        , requester(asker)
        , requesterTX(tx)
        , target(key)
        , exclude(excludes)
    {
    }

    void
    SearchJob::Completed(const udap_rc *router, bool timeout) const
    {
      if(job && job->hook)
      {
        if(router)
        {
          job->found = true;
          udap_rc_copy(&job->result, router);
        }
        job->hook(job);
      }
    }

    bool
    SearchJob::IsExpired(udap_time_t now) const
    {
      return now - started >= JobTimeout;
    }

    bool
    Bucket::FindClosest(const Key_t &target, Key_t &result) const
    {
      Key_t mindist;
      mindist.Fill(0xff);
      for(const auto &item : nodes)
      {
        auto curDist = item.first ^ target;
        if(curDist < mindist)
        {
          mindist = curDist;
          result  = item.first;
        }
      }
      return nodes.size() > 0;
    }

    bool
    Bucket::FindCloseExcluding(const Key_t &target, Key_t &result,
                               const std::set< Key_t > &exclude) const
    {
      Key_t maxdist;
      maxdist.Fill(0xff);
      Key_t mindist;
      mindist.Fill(0xff);
      for(const auto &item : nodes)
      {
        if(exclude.find(item.first) != exclude.end())
          continue;
        auto curDist = item.first ^ target;
        if(curDist < mindist)
        {
          mindist = curDist;
          result  = item.first;
        }
      }
      return mindist < maxdist;
    }

    void
    Bucket::PutNode(const Node &v)
    {
      nodes[v.ID] = v;
    }

    void
    Bucket::DelNode(const Key_t &k)
    {
      auto itr = nodes.find(k);
      if(itr != nodes.end())
        nodes.erase(itr);
    }

    Context::Context()
    {
      randombytes((byte_t *)&ids, sizeof(uint64_t));
    }

    Context::~Context()
    {
      if(nodes)
        delete nodes;
    }

    void
    Context::handle_cleaner_timer(void *u, uint64_t orig, uint64_t left)
    {
      if(left)
        return;
      Context *ctx = static_cast< Context * >(u);

      ctx->CleanupTX();
      ctx->ScheduleCleanupTimer();
    }

    void
    Context::LookupRouterRelayed(const Key_t &requester, uint64_t txid,
                                 const Key_t &target, bool recursive,
                                 std::vector< IMessage * > &replies)
    {
      if(target == ourKey)
      {
        // we are the target, give them our RC
        replies.push_back(new GotRouterMessage(requester, txid, &router->rc));
        return;
      }
      Key_t next;
      std::set< Key_t > excluding = {requester, ourKey};
      if(nodes->FindCloseExcluding(target, next, excluding))
      {
        if(next == target)
        {
          // we know it
          replies.push_back(
              new GotRouterMessage(requester, txid, nodes->nodes[target].rc));
        }
        else if(recursive)  // are we doing a recursive lookup?
        {
          if((requester ^ target) < (ourKey ^ target))
          {
            // we aren't closer to the target than next hop
            // so we won't ask neighboor recursively, tell them we don't have it
            udap::Info("we aren't closer to ", target, " than ", next,
                        " so we end it here");
            replies.push_back(new GotRouterMessage(requester, txid, nullptr));
          }
          else
          {
            // yeah, ask neighboor recursively
            LookupRouter(target, requester, txid, next);
          }
        }
        else  // otherwise tell them we don't have it
        {
          udap::Info("we don't have ", target,
                      " and this was an iterative request so telling ",
                      requester, " that we don't have it");
          replies.push_back(new GotRouterMessage(requester, txid, nullptr));
        }
      }
      else
      {
        // we don't know it and have no closer peers
        udap::Info("we don't have ", target,
                    " and have no closer peers so telling ", requester,
                    " that we don't have it");
        replies.push_back(new GotRouterMessage(requester, txid, nullptr));
      }
    }

    void
    Context::RemovePendingLookup(const Key_t &owner, uint64_t id)
    {
      TXOwner search;
      search.node = owner;
      search.txid = id;
      auto itr    = pendingTX.find(search);
      if(itr == pendingTX.end())
        return;
      pendingTX.erase(itr);
    }

    SearchJob *
    Context::FindPendingTX(const Key_t &owner, uint64_t id)
    {
      TXOwner search;
      search.node = owner;
      search.txid = id;
      auto itr    = pendingTX.find(search);
      if(itr == pendingTX.end())
        return nullptr;
      else
        return &itr->second;
    }

    void
    Context::CleanupTX()
    {
      auto now = udap_time_now_ms();
      udap::Debug("DHT tick");

      auto itr = pendingTX.begin();
      while(itr != pendingTX.end())
      {
        if(itr->second.IsExpired(now))
        {
          itr->second.Completed(nullptr, true);
          itr = pendingTX.erase(itr);
        }
        else
          ++itr;
      }
    }

    void
    Context::Init(const Key_t &us, udap_router *r)
    {
      router = r;
      ourKey = us;
      nodes  = new Bucket(ourKey);
      udap::Debug("intialize dht with key ", ourKey);
    }

    void
    Context::ScheduleCleanupTimer()
    {
      udap_logic_call_later(router->logic,
                             {1000, this, &handle_cleaner_timer});
    }

    void
    Context::LookupRouter(const Key_t &target, const Key_t &whoasked,
                          uint64_t txid, const Key_t &askpeer,
                          udap_router_lookup_job *job, bool iterative,
                          std::set< Key_t > excludes)
    {
      if(target.IsZero() || whoasked.IsZero() || askpeer.IsZero())
      {
        return;
      }
      auto id = ++ids;
      TXOwner ownerKey;
      ownerKey.node = askpeer;
      ownerKey.txid = id;
      if(txid == 0)
        txid = id;

      pendingTX[ownerKey] = SearchJob(whoasked, txid, target, job, excludes);

      udap::Info("Asking ", askpeer, " for router ", target, " for ",
                  whoasked);
      auto msg          = new udap::DHTImmeidateMessage(askpeer);
      auto dhtmsg       = new FindRouterMessage(askpeer, target, id);
      dhtmsg->iterative = iterative;
      msg->msgs.push_back(dhtmsg);
      router->SendToOrQueue(askpeer, msg);
    }

    void
    Context::LookupRouterViaJob(udap_router_lookup_job *job)
    {
      Key_t peer;
      if(nodes->FindClosest(job->target, peer))
        LookupRouter(job->target, ourKey, 0, peer, job);
      else if(job->hook)
      {
        job->found = false;
        job->hook(job);
      }
    }

    void
    Context::queue_router_lookup(void *user)
    {
      udap_router_lookup_job *job =
          static_cast< udap_router_lookup_job * >(user);
      job->dht->impl.LookupRouterViaJob(job);
    }

  }  // namespace dht
}  // namespace udap

udap_dht_context::udap_dht_context(udap_router *router)
{
  parent = router;
}

extern "C" {
struct udap_dht_context *
udap_dht_context_new(struct udap_router *router)
{
  return new udap_dht_context(router);
}

void
udap_dht_context_free(struct udap_dht_context *ctx)
{
  delete ctx;
}

void
udap_dht_put_peer(struct udap_dht_context *ctx, struct udap_rc *rc)

{
  udap::dht::Node n(rc);
  ctx->impl.nodes->PutNode(n);
}

void
udap_dht_remove_peer(struct udap_dht_context *ctx, const byte_t *id)
{
  udap::dht::Key_t k = id;
  ctx->impl.nodes->DelNode(k);
}

void
udap_dht_set_msg_handler(struct udap_dht_context *ctx,
                          udap_dht_msg_handler handler)
{
  ctx->impl.custom_handler = handler;
}

void
udap_dht_allow_transit(udap_dht_context *ctx)
{
  ctx->impl.allowTransit = true;
}

void
udap_dht_context_start(struct udap_dht_context *ctx, const byte_t *key)
{
  ctx->impl.Init(key, ctx->parent);
}

void
udap_dht_lookup_router(struct udap_dht_context *ctx,
                        struct udap_router_lookup_job *job)
{
  job->dht   = ctx;
  job->found = false;
  udap_logic_queue_job(ctx->parent->logic,
                        {job, &udap::dht::Context::queue_router_lookup});
}
}
