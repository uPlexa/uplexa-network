#ifndef UDAP_DHT_HPP_
#define UDAP_DHT_HPP_
#include <udap/buffer.h>
#include <udap/dht.h>
#include <udap/router.h>
#include <udap/router_contact.h>
#include <udap/time.h>
#include <udap/aligned.hpp>

#include <array>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

namespace udap
{
  namespace dht
  {
    const size_t MAX_MSG_SIZE = 2048;

    struct Key_t : public udap::AlignedBuffer< 32 >
    {
      Key_t(const byte_t* val) : udap::AlignedBuffer< 32 >(val)
      {
      }

      Key_t() : udap::AlignedBuffer< 32 >()
      {
      }

      Key_t
      operator^(const Key_t& other) const
      {
        Key_t dist;
        for(size_t idx = 0; idx < 4; ++idx)
          dist.l[idx] = l[idx] ^ other.l[idx];
        return dist;
      }

      bool
      operator<(const Key_t& other) const
      {
        return memcmp(data_l(), other.data_l(), 32) < 0;
      }
    };

    struct Node
    {
      udap_rc* rc;

      Key_t ID;

      Node() : rc(nullptr)
      {
        ID.Zero();
      }

      Node(udap_rc* other) : rc(other)
      {
        ID = other->pubkey;
      }
    };

    struct SearchJob
    {
      const static uint64_t JobTimeout = 30000;

      SearchJob();

      SearchJob(const Key_t& requester, uint64_t requesterTX,
                const Key_t& target, udap_router_lookup_job* job,
                const std::set< Key_t >& excludes);

      void
      Completed(const udap_rc* router, bool timeout = false) const;

      bool
      IsExpired(udap_time_t now) const;

      udap_router_lookup_job* job = nullptr;
      udap_time_t started;
      Key_t requester;
      uint64_t requesterTX;
      Key_t target;
      std::set< Key_t > exclude;
    };

    struct XorMetric
    {
      const Key_t& us;

      XorMetric(const Key_t& ourKey) : us(ourKey){};

      bool
      operator()(const Key_t& left, const Key_t& right) const
      {
        return (us ^ left) < (us ^ right);
      };
    };

    struct IMessage
    {
      virtual ~IMessage(){};

      IMessage(const Key_t& from) : From(from)
      {
      }

      virtual bool
      BEncode(udap_buffer_t* buf) const = 0;

      virtual bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* val) = 0;

      virtual bool
      HandleMessage(udap_router* router,
                    std::vector< IMessage* >& replies) const = 0;

      Key_t From;
    };

    IMessage*
    DecodeMessage(const Key_t& from, udap_buffer_t* buf);

    bool
    DecodeMesssageList(const Key_t& from, udap_buffer_t* buf,
                       std::vector< IMessage* >& dst);

    struct Bucket
    {
      typedef std::map< Key_t, Node, XorMetric > BucketStorage_t;

      Bucket(const Key_t& us) : nodes(XorMetric(us)){};

      bool
      FindClosest(const Key_t& target, Key_t& result) const;

      bool
      FindCloseExcluding(const Key_t& target, Key_t& result,
                         const std::set< Key_t >& exclude) const;

      void
      PutNode(const Node& val);

      void
      DelNode(const Key_t& key);

      BucketStorage_t nodes;
    };

    struct Context
    {
      Context();
      ~Context();

      udap_dht_msg_handler custom_handler = nullptr;

      SearchJob*
      FindPendingTX(const Key_t& owner, uint64_t txid);

      void
      RemovePendingLookup(const Key_t& owner, uint64_t txid);

      void
      LookupRouter(const Key_t& target, const Key_t& whoasked,
                   uint64_t whoaskedTX, const Key_t& askpeer,
                   udap_router_lookup_job* job = nullptr,
                   bool iterative = false, std::set< Key_t > excludes = {});

      void
      LookupRouterViaJob(udap_router_lookup_job* job);

      void
      LookupRouterRelayed(const Key_t& requester, uint64_t txid,
                          const Key_t& target, bool recursive,
                          std::vector< IMessage* >& replies);

      void
      Init(const Key_t& us, udap_router* router);

      void
      QueueRouterLookup(udap_router_lookup_job* job);

      static void
      handle_cleaner_timer(void* user, uint64_t orig, uint64_t left);

      static void
      queue_router_lookup(void* user);

      udap_router* router = nullptr;
      Bucket* nodes        = nullptr;
      bool allowTransit    = false;

      const Key_t&
      OurKey() const
      {
        return ourKey;
      }

     private:
      void
      ScheduleCleanupTimer();

      void
      CleanupTX();

      uint64_t ids;

      struct TXOwner
      {
        Key_t node;
        uint64_t txid = 0;

        bool
        operator==(const TXOwner& other) const
        {
          return txid == other.txid && node == other.node;
        }
        bool
        operator<(const TXOwner& other) const
        {
          return txid < other.txid || node < other.node;
        }
      };

      struct TXOwnerHash
      {
        std::size_t
        operator()(TXOwner const& o) const noexcept
        {
          std::size_t sz2;
          memcpy(&sz2, &o.node[0], sizeof(std::size_t));
          return o.txid ^ (sz2 << 1);
        }
      };

      std::unordered_map< TXOwner, SearchJob, TXOwnerHash > pendingTX;
      Key_t ourKey;
    };

    struct GotRouterMessage : public IMessage
    {
      GotRouterMessage(const Key_t& from) : IMessage(from)
      {
      }
      GotRouterMessage(const Key_t& from, uint64_t id, const udap_rc* result)
          : IMessage(from), txid(id)
      {
        if(result)
        {
          R.emplace_back();
          udap_rc_clear(&R.back());
          udap_rc_copy(&R.back(), result);
        }
      }

      ~GotRouterMessage();

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* val);

      bool
      HandleMessage(udap_router* router,
                    std::vector< IMessage* >& replies) const;

      std::vector< udap_rc > R;
      uint64_t txid    = 0;
      uint64_t version = 0;
    };

    struct FindRouterMessage : public IMessage
    {
      FindRouterMessage(const Key_t& from) : IMessage(from)
      {
      }

      FindRouterMessage(const Key_t& from, const Key_t& target, uint64_t id)
          : IMessage(from), K(target), txid(id)
      {
      }

      ~FindRouterMessage();

      bool
      BEncode(udap_buffer_t* buf) const;

      bool
      DecodeKey(udap_buffer_t key, udap_buffer_t* val);

      bool
      HandleMessage(udap_router* router,
                    std::vector< IMessage* >& replies) const;

      Key_t K;
      bool iterative   = false;
      uint64_t txid    = 0;
      uint64_t version = 0;
    };
  }  // namespace dht
}  // namespace udap

struct udap_dht_context
{
  udap::dht::Context impl;
  udap_router* parent;
  udap_dht_context(udap_router* router);
};

#endif
