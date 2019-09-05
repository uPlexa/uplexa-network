#include <udap/path.hpp>
#include <udap/routing/handler.hpp>
#include "buffer.hpp"
#include "router.hpp"

namespace udap
{
  namespace path
  {
    TransitHop::TransitHop()
    {
    }

    bool
    TransitHop::Expired(udap_time_t now) const
    {
      return now - started > lifetime;
    }

    TransitHopInfo::TransitHopInfo(const TransitHopInfo& other)
        : txID(other.txID)
        , rxID(other.rxID)
        , upstream(other.upstream)
        , downstream(other.downstream)
    {
    }

    TransitHopInfo::TransitHopInfo(const RouterID& down,
                                   const LR_CommitRecord& record)
        : txID(record.txid)
        , rxID(record.rxid)
        , upstream(record.nextHop)
        , downstream(down)
    {
    }

    TransitHop::TransitHop(const TransitHop& other)
        : info(other.info)
        , pathKey(other.pathKey)
        , started(other.started)
        , lifetime(other.lifetime)
        , version(other.version)
    {
    }

    bool
    TransitHop::SendRoutingMessage(const udap::routing::IMessage* msg,
                                   udap_router* r)
    {
      byte_t tmp[MAX_LINK_MSG_SIZE / 2];
      auto buf = udap::StackBuffer< decltype(tmp) >(tmp);
      if(!msg->BEncode(&buf))
      {
        udap::Error("failed to encode routing message");
        return false;
      }
      TunnelNonce N;
      N.Randomize();
      // rewind
      buf.sz  = buf.cur - buf.base;
      buf.cur = buf.base;
      return HandleDownstream(buf, N, r);
    }

    bool
    TransitHop::HandleDownstream(udap_buffer_t buf, const TunnelNonce& Y,
                                 udap_router* r)
    {
      RelayDownstreamMessage* msg = new RelayDownstreamMessage;
      msg->pathid                 = info.rxID;
      msg->Y                      = Y;

      r->crypto.xchacha20(buf, pathKey, Y);
      msg->X = buf;
      udap::Info("relay ", msg->X.size(), " bytes downstream from ",
                  info.upstream, " to ", info.downstream);
      return r->SendToOrQueue(info.downstream, msg);
    }

    bool
    TransitHop::HandleUpstream(udap_buffer_t buf, const TunnelNonce& Y,
                               udap_router* r)
    {
      r->crypto.xchacha20(buf, pathKey, Y);
      if(info.upstream == RouterID(r->pubkey()))
      {
        return m_MessageParser.ParseMessageBuffer(buf, this, r);
      }
      else
      {
        RelayUpstreamMessage* msg = new RelayUpstreamMessage;
        msg->pathid               = info.txID;
        msg->Y                    = Y;

        msg->X = buf;
        udap::Info("relay ", msg->X.size(), " bytes upstream from ",
                    info.downstream, " to ", info.upstream);
        return r->SendToOrQueue(info.upstream, msg);
      }
    }

    bool
    TransitHop::HandleDHTMessage(const udap::dht::IMessage* msg,
                                 udap_router* r)
    {
      // TODO: implement me
      return false;
    }

    bool
    TransitHop::HandlePathLatencyMessage(
        const udap::routing::PathLatencyMessage* msg, udap_router* r)
    {
      udap::routing::PathLatencyMessage reply;
      reply.L = msg->T;
      udap::Info("got latency message ", msg->T);
      return SendRoutingMessage(&reply, r);
    }

    bool
    TransitHop::HandlePathConfirmMessage(
        const udap::routing::PathConfirmMessage* msg, udap_router* r)
    {
      udap::Warn("unwarrented path confirm message on ", info);
      return false;
    }

    bool
    TransitHop::HandlePathTransferMessage(
        const udap::routing::PathTransferMessage* msg, udap_router* r)
    {
      auto path = r->paths.GetByDownstream(r->pubkey(), msg->P);
      if(path)
      {
        return path->HandleDownstream(msg->T.Buffer(), msg->Y, r);
      }
      udap::Warn("No such path for path transfer pathid=", msg->P);
      return false;
    }

    bool
    TransitHop::HandleHiddenServiceData(udap_buffer_t buf, udap_router* r)
    {
      udap::Warn("unwarrented hidden service data on ", info);
      return false;
    }

  }  // namespace path
}  // namespace udap
