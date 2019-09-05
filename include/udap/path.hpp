#ifndef UDAP_PATH_HPP
#define UDAP_PATH_HPP
#include <udap/path.h>
#include <udap/router.h>
#include <udap/time.h>
#include <udap/aligned.hpp>
#include <udap/crypto.hpp>
#include <udap/dht.hpp>
#include <udap/endpoint.hpp>
#include <udap/messages/relay.hpp>
#include <udap/messages/relay_commit.hpp>
#include <udap/path_types.hpp>
#include <udap/pathset.hpp>
#include <udap/router_id.hpp>
#include <udap/routing/handler.hpp>
#include <udap/routing/message.hpp>

#include <list>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace udap
{
  namespace path
  {
    struct TransitHopInfo
    {
      TransitHopInfo() = default;
      TransitHopInfo(const TransitHopInfo& other);
      TransitHopInfo(const RouterID& down, const LR_CommitRecord& record);

      PathID_t txID, rxID;
      RouterID upstream;
      RouterID downstream;

      friend std::ostream&
      operator<<(std::ostream& out, const TransitHopInfo& info)
      {
        out << "<tx=" << info.txID << " rx=" << info.rxID;
        out << " upstream=" << info.upstream
            << " downstream=" << info.downstream;
        return out << ">";
      }

      bool
      operator==(const TransitHopInfo& other) const
      {
        return txID == other.txID && rxID == other.rxID
            && upstream == other.upstream && downstream == other.downstream;
      }

      bool
      operator!=(const TransitHopInfo& other) const
      {
        return !(*this == other);
      }

      bool
      operator<(const TransitHopInfo& other) const
      {
        return txID < other.txID || rxID < other.rxID
            || upstream < other.upstream || downstream < other.downstream;
      }

      struct Hash
      {
        std::size_t
        operator()(TransitHopInfo const& a) const
        {
          std::size_t idx0, idx1, idx2, idx3;
          memcpy(&idx0, a.upstream, sizeof(std::size_t));
          memcpy(&idx1, a.downstream, sizeof(std::size_t));
          memcpy(&idx2, a.txID, sizeof(std::size_t));
          memcpy(&idx3, a.rxID, sizeof(std::size_t));
          return idx0 ^ idx1 ^ idx2;
        }
      };
    };

    struct PathIDHash
    {
      std::size_t
      operator()(const PathID_t& a) const
      {
        std::size_t idx0;
        memcpy(&idx0, a, sizeof(std::size_t));
        return idx0;
      }
    };

    struct IHopHandler
    {
      virtual ~IHopHandler(){};

      virtual bool
      Expired(udap_time_t now) const = 0;

      virtual bool
      SendRoutingMessage(const udap::routing::IMessage* msg,
                         udap_router* r) = 0;

      // handle data in upstream direction
      virtual bool
      HandleUpstream(udap_buffer_t X, const TunnelNonce& Y,
                     udap_router* r) = 0;

      // handle data in downstream direction
      virtual bool
      HandleDownstream(udap_buffer_t X, const TunnelNonce& Y,
                       udap_router* r) = 0;
    };

    struct TransitHop : public IHopHandler,
                        public udap::routing::IMessageHandler
    {
      TransitHop();

      TransitHop(const TransitHop& other);

      TransitHopInfo info;
      SharedSecret pathKey;
      udap_time_t started = 0;
      // 10 minutes default
      udap_time_t lifetime = DEFAULT_PATH_LIFETIME;
      udap_proto_version_t version;

      udap::routing::InboundMessageParser m_MessageParser;

      friend std::ostream&
      operator<<(std::ostream& out, const TransitHop& h)
      {
        return out << "[TransitHop " << h.info << " started=" << h.started
                   << " lifetime=" << h.lifetime << "]";
      }

      bool
      Expired(udap_time_t now) const;

      // send routing message when end of path
      bool
      SendRoutingMessage(const udap::routing::IMessage* msg, udap_router* r);

      // handle routing message when end of path
      bool
      HandleRoutingMessage(const udap::routing::IMessage* msg,
                           udap_router* r);

      bool
      HandlePathConfirmMessage(const udap::routing::PathConfirmMessage* msg,
                               udap_router* r);
      bool
      HandlePathTransferMessage(const udap::routing::PathTransferMessage* msg,
                                udap_router* r);
      bool
      HandlePathLatencyMessage(const udap::routing::PathLatencyMessage* msg,
                               udap_router* r);

      bool
      HandleDHTMessage(const udap::dht::IMessage* msg, udap_router* r);

      bool
      HandleHiddenServiceData(udap_buffer_t buf, udap_router* r);

      // handle data in upstream direction
      bool
      HandleUpstream(udap_buffer_t X, const TunnelNonce& Y, udap_router* r);

      // handle data in downstream direction
      bool
      HandleDownstream(udap_buffer_t X, const TunnelNonce& Y, udap_router* r);
    };

    /// configuration for a single hop when building a path
    struct PathHopConfig
    {
      /// path id
      PathID_t txID, rxID;
      // router contact of router
      udap_rc router;
      // temp public encryption key
      SecretKey commkey;
      /// shared secret at this hop
      SharedSecret shared;
      /// next hop's router id
      RouterID upstream;
      /// nonce for key exchange
      TunnelNonce nonce;
      // lifetime
      udap_time_t lifetime = DEFAULT_PATH_LIFETIME;

      ~PathHopConfig();
      PathHopConfig();
    };

    /// A path we made
    struct Path : public IHopHandler, public udap::routing::IMessageHandler
    {
      typedef std::function< void(Path*) > BuildResultHookFunc;
      typedef std::vector< PathHopConfig > HopList;
      HopList hops;
      udap_time_t buildStarted;
      PathStatus status;

      Path(udap_path_hops* path);

      void
      SetBuildResultHook(BuildResultHookFunc func);

      bool
      Expired(udap_time_t now) const;

      bool
      SendRoutingMessage(const udap::routing::IMessage* msg, udap_router* r);

      bool
      HandlePathConfirmMessage(const udap::routing::PathConfirmMessage* msg,
                               udap_router* r);

      bool
      HandlePathLatencyMessage(const udap::routing::PathLatencyMessage* msg,
                               udap_router* r);

      bool
      HandlePathTransferMessage(const udap::routing::PathTransferMessage* msg,
                                udap_router* r);

      bool
      HandleDHTMessage(const udap::dht::IMessage* msg, udap_router* r);

      bool
      HandleRoutingMessage(udap_buffer_t buf, udap_router* r);

      bool
      HandleHiddenServiceData(udap_buffer_t buf, udap_router* r);

      // handle data in upstream direction
      bool
      HandleUpstream(udap_buffer_t X, const TunnelNonce& Y, udap_router* r);

      // handle data in downstream direction
      bool
      HandleDownstream(udap_buffer_t X, const TunnelNonce& Y, udap_router* r);

      // Is this deprecated?
      // nope not deprecated :^DDDD
      const PathID_t&
      TXID() const;

      const PathID_t&
      RXID() const;

      RouterID
      Upstream() const;

      udap_time_t Latency = 0;

     protected:
      udap::routing::InboundMessageParser m_InboundMessageParser;

     private:
      BuildResultHookFunc m_BuiltHook;
      udap_time_t m_LastLatencyTestTime = 0;
      uint64_t m_LastLatencyTestID       = 0;
    };

    enum PathBuildStatus
    {
      ePathBuildSuccess,
      ePathBuildTimeout,
      ePathBuildReject
    };

    struct PathContext
    {
      PathContext(udap_router* router);
      ~PathContext();

      /// called from router tick function
      void
      ExpirePaths();

      /// called from router tick function
      /// builds all paths we need to build at current tick
      void
      BuildPaths();

      ///  track a path builder with this context
      void
      AddPathBuilder(udap_pathbuilder_context* set);

      void
      AllowTransit();
      void
      RejectTransit();

      bool
      AllowingTransit() const;

      bool
      HasTransitHop(const TransitHopInfo& info);

      bool
      HandleRelayCommit(const LR_CommitMessage* msg);

      void
      PutTransitHop(TransitHop* hop);

      IHopHandler*
      GetByUpstream(const RouterID& id, const PathID_t& path);

      IHopHandler*
      GetByDownstream(const RouterID& id, const PathID_t& path);

      bool
      ForwardLRCM(const RouterID& nextHop,
                  std::deque< EncryptedFrame >& frames);

      bool
      HopIsUs(const PubKey& k) const;

      bool
      HandleLRUM(const RelayUpstreamMessage* msg);

      bool
      HandleLRDM(const RelayDownstreamMessage* msg);

      void
      AddOwnPath(PathSet* set, Path* p);

      typedef std::multimap< PathID_t, TransitHop* > TransitHopsMap_t;

      typedef std::pair< std::mutex, TransitHopsMap_t > SyncTransitMap_t;

      // maps path id -> pathset owner of path
      typedef std::map< PathID_t, PathSet* > OwnedPathsMap_t;

      typedef std::pair< std::mutex, OwnedPathsMap_t > SyncOwnedPathsMap_t;

      udap_threadpool*
      Worker();

      udap_crypto*
      Crypto();

      udap_logic*
      Logic();

      udap_router*
      Router();

      byte_t*
      EncryptionSecretKey();

      const byte_t*
      OurRouterID() const;

     private:
      udap_router* m_Router;
      SyncTransitMap_t m_TransitPaths;
      SyncTransitMap_t m_Paths;
      SyncOwnedPathsMap_t m_OurPaths;
      std::list< udap_pathbuilder_context* > m_PathBuilders;
      bool m_AllowTransit;
    };
  }  // namespace path
}  // namespace udap

#endif
