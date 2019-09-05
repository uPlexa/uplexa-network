#include <udap/nodedb.h>
#include <udap/path.hpp>

#include "pathbuilder.hpp"
#include "router.hpp"

namespace udap
{
  template < typename User >
  struct AsyncPathKeyExchangeContext
  {
    typedef udap::path::Path Path_t;
    typedef udap::path::PathSet PathSet_t;
    PathSet_t* pathset = nullptr;
    Path_t* path       = nullptr;
    typedef void (*Handler)(AsyncPathKeyExchangeContext< User >*);
    User* user               = nullptr;
    Handler result           = nullptr;
    size_t idx               = 0;
    udap_threadpool* worker = nullptr;
    udap_logic* logic       = nullptr;
    udap_crypto* crypto     = nullptr;
    LR_CommitMessage* LRCM   = nullptr;

    static void
    HandleDone(void* u)
    {
      AsyncPathKeyExchangeContext< User >* ctx =
          static_cast< AsyncPathKeyExchangeContext< User >* >(u);
      ctx->result(ctx);
    }

    static void
    GenerateNextKey(void* u)
    {
      AsyncPathKeyExchangeContext< User >* ctx =
          static_cast< AsyncPathKeyExchangeContext< User >* >(u);

      // current hop
      auto& hop   = ctx->path->hops[ctx->idx];
      auto& frame = ctx->LRCM->frames[ctx->idx];
      // generate key
      ctx->crypto->encryption_keygen(hop.commkey);
      hop.nonce.Randomize();
      // do key exchange
      if(!ctx->crypto->dh_client(hop.shared, hop.router.enckey, hop.commkey,
                                 hop.nonce))
      {
        udap::Error("Failed to generate shared key for path build");
        abort();
        return;
      }
      ++ctx->idx;

      bool isFarthestHop = ctx->idx == ctx->path->hops.size();

      if(isFarthestHop)
      {
        hop.upstream = hop.router.pubkey;
      }
      else
      {
        hop.upstream = ctx->path->hops[ctx->idx].router.pubkey;
      }

      // build record
      LR_CommitRecord record;
      record.version     = UDAP_PROTO_VERSION;
      record.txid        = hop.txID;
      record.rxid        = hop.rxID;
      record.tunnelNonce = hop.nonce;
      record.nextHop     = hop.upstream;
      record.commkey     = udap::seckey_topublic(hop.commkey);

      auto buf = frame.Buffer();
      buf->cur = buf->base + EncryptedFrame::OverheadSize;
      // encode record
      if(!record.BEncode(buf))
      {
        // failed to encode?
        udap::Error("Failed to generate Commit Record");
        return;
      }
      // use ephameral keypair for frame
      SecretKey framekey;
      ctx->crypto->encryption_keygen(framekey);
      if(!frame.EncryptInPlace(framekey, hop.router.enckey, ctx->crypto))
      {
        udap::Error("Failed to encrypt LRCR");
        return;
      }

      if(isFarthestHop)
      {
        // farthest hop
        udap_logic_queue_job(ctx->logic, {ctx, &HandleDone});
      }
      else
      {
        // next hop
        udap_threadpool_queue_job(ctx->worker, {ctx, &GenerateNextKey});
      }
    }

    AsyncPathKeyExchangeContext(udap_crypto* c) : crypto(c)
    {
    }

    /// Generate all keys asynchronously and call hadler when done
    void
    AsyncGenerateKeys(Path_t* p, udap_logic* l, udap_threadpool* pool,
                      User* u, Handler func)
    {
      path   = p;
      logic  = l;
      user   = u;
      result = func;
      worker = pool;
      LRCM   = new LR_CommitMessage;

      for(size_t idx = 0; idx < MAXHOPS; ++idx)
      {
        LRCM->frames.emplace_back();
        LRCM->frames.back().Randomize();
      }
      udap_threadpool_queue_job(pool, {this, &GenerateNextKey});
    }
  };

  void
  pathbuilder_generated_keys(
      AsyncPathKeyExchangeContext< udap_pathbuild_job >* ctx)
  {
    auto remote = ctx->path->Upstream();
    udap::Info("Generated LRCM to ", remote);
    auto router = ctx->user->router;
    if(!router->SendToOrQueue(remote, ctx->LRCM))
    {
      udap::Error("failed to send LRCM");
      return;
    }
    ctx->path->status       = udap::path::ePathBuilding;
    ctx->path->buildStarted = udap_time_now_ms();
    router->paths.AddOwnPath(ctx->pathset, ctx->path);
    ctx->user->pathBuildStarted(ctx->user);
  }

  void
  pathbuilder_start_build(void* user)
  {
    udap_pathbuild_job* job = static_cast< udap_pathbuild_job* >(user);
    // select hops
    size_t idx     = 0;
    udap_rc* prev = nullptr;
    while(idx < job->hops.numHops)
    {
      udap_rc* rc = &job->hops.hops[idx].router;
      udap_rc_clear(rc);
      job->selectHop(job->router->nodedb, prev, rc, idx);
      prev = rc;
      ++idx;
    }

    // async generate keys
    AsyncPathKeyExchangeContext< udap_pathbuild_job >* ctx =
        new AsyncPathKeyExchangeContext< udap_pathbuild_job >(
            &job->router->crypto);
    ctx->pathset = job->context;
    auto path    = new udap::path::Path(&job->hops);
    path->SetBuildResultHook(std::bind(&udap::path::PathSet::HandlePathBuilt,
                                       ctx->pathset, std::placeholders::_1));
    ctx->AsyncGenerateKeys(path, job->router->logic, job->router->tp, job,
                           &pathbuilder_generated_keys);
  }
}  // namespace udap

udap_pathbuilder_context::udap_pathbuilder_context(
    udap_router* p_router, struct udap_dht_context* p_dht)
    // TODO: hardcoded value
    : udap::path::PathSet(4), router(p_router), dht(p_dht)
{
  p_router->paths.AddPathBuilder(this);
}

void
udap_pathbuilder_context::BuildOne()
{
  udap_pathbuild_job* job = new udap_pathbuild_job;
  job->context             = this;
  job->selectHop           = nullptr;
  job->hops.numHops        = 4;
  job->user                = nullptr;
  job->pathBuildStarted    = [](udap_pathbuild_job* j) { delete j; };
  udap_pathbuilder_build_path(job);
}

extern "C" {
struct udap_pathbuilder_context*
udap_pathbuilder_context_new(struct udap_router* router,
                              struct udap_dht_context* dht)
{
  return new udap_pathbuilder_context(router, dht);
}

void
udap_pathbuilder_context_free(struct udap_pathbuilder_context* ctx)
{
  delete ctx;
}

void
udap_pathbuilder_build_path(struct udap_pathbuild_job* job)
{
  if(!job->context)
  {
    udap::Error("failed to build path because no context is set in job");
    return;
  }
  job->router = job->context->router;
  if(job->selectHop == nullptr)
    job->selectHop = &udap_nodedb_select_random_hop;
  udap_logic_queue_job(job->router->logic,
                        {job, &udap::pathbuilder_start_build});
}
}  // end extern c
