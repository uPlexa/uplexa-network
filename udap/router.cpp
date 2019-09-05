#include "router.hpp"
#include <udap/iwp.h>
#include <udap/link.h>
#include <udap/proto.h>
#include <udap/router.h>
#include <udap/link_message.hpp>
#include <udap/messages/discard.hpp>

#include "buffer.hpp"
#include "encode.hpp"
#include "logger.hpp"
#include "net.hpp"
#include "str.hpp"

#include <fstream>

namespace udap
{
  void
  router_iter_config(udap_config_iterator *iter, const char *section,
                     const char *key, const char *val);

  struct async_verify_context
  {
    udap_router *router;
    udap_link_establish_job *establish_job;
  };

}  // namespace udap

udap_router::udap_router()
    : ready(false)
    , paths(this)
    , dht(udap_dht_context_new(this))
    , inbound_link_msg_parser(this)
    , explorePool(udap_pathbuilder_context_new(this, dht))

{
  udap_rc_clear(&rc);
}

udap_router::~udap_router()
{
  udap_dht_context_free(dht);
  udap_rc_free(&rc);
}

bool
udap_router::HandleRecvLinkMessage(udap_link_session *session,
                                    udap_buffer_t buf)
{
  return inbound_link_msg_parser.ProcessFrom(session, buf);
}

bool
udap_router::SendToOrQueue(const udap::RouterID &remote,
                            const udap::ILinkMessage *msg)
{
  udap_link *chosen = nullptr;
  if(!outboundLink->has_session_to(outboundLink, remote))
  {
    for(auto link : inboundLinks)
    {
      if(link->has_session_to(link, remote))
      {
        chosen = link;
        break;
      }
    }
  }
  else
    chosen = outboundLink;

  if(chosen)
  {
    SendTo(remote, msg, chosen);
    delete msg;
    return true;
  }
  // this will create an entry in the obmq if it's not already there
  auto itr = outboundMesssageQueue.find(remote);
  if(itr == outboundMesssageQueue.end())
  {
    outboundMesssageQueue.emplace(std::make_pair(remote, MessageQueue()));
  }
  outboundMesssageQueue[remote].push(msg);

  // we don't have an open session to that router right now
  auto rc = udap_nodedb_get_rc(nodedb, remote);
  if(rc)
  {
    // try connecting directly as the rc is loaded from disk
    udap_router_try_connect(this, rc, 10);
    return true;
  }
  // try requesting the rc from the disk
  udap_async_load_rc *job = new udap_async_load_rc;
  job->diskworker          = disk;
  job->nodedb              = nodedb;
  job->logic               = logic;
  job->user                = this;
  job->hook                = &HandleAsyncLoadRCForSendTo;
  memcpy(job->pubkey, remote, PUBKEYSIZE);
  udap_nodedb_async_load_rc(job);

  return true;
}

void
udap_router::HandleAsyncLoadRCForSendTo(udap_async_load_rc *job)
{
  udap_router *router = static_cast< udap_router * >(job->user);
  if(job->loaded)
  {
    udap_router_try_connect(router, &job->rc, 10);
  }
  else
  {
    // we don't have the RC locally so do a dht lookup
    udap_router_lookup_job *lookup = new udap_router_lookup_job;
    lookup->user                    = router;
    memcpy(lookup->target, job->pubkey, PUBKEYSIZE);
    lookup->hook = &HandleDHTLookupForSendTo;
    udap_dht_lookup_router(router->dht, lookup);
  }
  delete job;
}

void
udap_router::HandleDHTLookupForSendTo(udap_router_lookup_job *job)
{
  udap_router *self = static_cast< udap_router * >(job->user);
  if(job->found)
  {
    udap_router_try_connect(self, &job->result, 10);
  }
  else
  {
    self->DiscardOutboundFor(job->target);
  }
  delete job;
}

void
udap_router::try_connect(fs::path rcfile)
{
  byte_t tmp[MAX_RC_SIZE];
  udap_rc remote = {0};
  udap_buffer_t buf;
  udap::StackBuffer< decltype(tmp) >(buf, tmp);
  // open file
  {
    std::ifstream f(rcfile, std::ios::binary);
    if(f.is_open())
    {
      f.seekg(0, std::ios::end);
      size_t sz = f.tellg();
      f.seekg(0, std::ios::beg);
      if(sz <= buf.sz)
      {
        f.read((char *)buf.base, sz);
      }
      else
        udap::Error(rcfile, " too large");
    }
    else
    {
      udap::Error("failed to open ", rcfile);
      return;
    }
  }
  if(udap_rc_bdecode(&remote, &buf))
  {
    if(udap_rc_verify_sig(&crypto, &remote))
    {
      udap::Debug("verified signature");
      if(!udap_router_try_connect(this, &remote, 10))
      {
        udap::Warn("session already made");
      }
    }
    else
      udap::Error("failed to verify signature of RC", rcfile);
  }
  else
    udap::Error("failed to decode RC");

  udap_rc_free(&remote);
}

bool
udap_router::EnsureIdentity()
{
  if(!EnsureEncryptionKey())
    return false;
  return udap_findOrCreateIdentity(&crypto, ident_keyfile.c_str(), identity);
}

bool
udap_router::EnsureEncryptionKey()
{
  return udap_findOrCreateEncryption(&crypto, encryption_keyfile.c_str(),
                                      &this->encryption);
}

void
udap_router::AddInboundLink(struct udap_link *link)
{
  inboundLinks.push_back(link);
}

bool
udap_router::Ready()
{
  return outboundLink != nullptr;
}

bool
udap_router::SaveRC()
{
  udap::Debug("verify RC signature");
  if(!udap_rc_verify_sig(&crypto, &rc))
  {
    udap::Error("RC has bad signature not saving");
    return false;
  }

  byte_t tmp[MAX_RC_SIZE];
  auto buf = udap::StackBuffer< decltype(tmp) >(tmp);

  if(udap_rc_bencode(&rc, &buf))
  {
    std::ofstream f(our_rc_file);
    if(f.is_open())
    {
      f.write((char *)buf.base, buf.cur - buf.base);
      udap::Info("our RC saved to ", our_rc_file.c_str());
      return true;
    }
  }
  udap::Error("did not save RC to ", our_rc_file.c_str());
  return false;
}

void
udap_router::Close()
{
  for(auto link : inboundLinks)
  {
    link->stop_link(link);
    link->free_impl(link);
    delete link;
  }
  inboundLinks.clear();

  outboundLink->stop_link(outboundLink);
  outboundLink->free_impl(outboundLink);
  delete outboundLink;
  outboundLink = nullptr;
}

void
udap_router::connect_job_retry(void *user, uint64_t orig, uint64_t left)
{
  if(left)
    return;
  udap_link_establish_job *job =
      static_cast< udap_link_establish_job * >(user);
  udap::Addr remote = job->ai;
  if(job->link)
  {
    udap::Info("trying to establish session again with ", remote);
    job->link->try_establish(job->link, job);
  }
  else
  {
    udap::Error("establish session retry failed, no link for ", remote);
  }
}

void
udap_router::on_verify_client_rc(udap_async_verify_rc *job)
{
  udap::async_verify_context *ctx =
      static_cast< udap::async_verify_context * >(job->user);
  udap::PubKey pk = job->rc.pubkey;
  udap_rc_free(&job->rc);
  ctx->router->pendingEstablishJobs.erase(pk);
  delete ctx;
}

void
udap_router::on_verify_server_rc(udap_async_verify_rc *job)
{
  udap::async_verify_context *ctx =
      static_cast< udap::async_verify_context * >(job->user);
  auto router = ctx->router;
  udap::Debug("rc verified? ", job->valid ? "valid" : "invalid");
  udap::PubKey pk(job->rc.pubkey);
  if(!job->valid)
  {
    udap::Warn("invalid server RC");
    if(ctx->establish_job)
    {
      // was an outbound attempt
      auto session = ctx->establish_job->session;
      if(session)
        session->close(session);
    }
    udap_rc_free(&job->rc);
    router->pendingEstablishJobs.erase(pk);
    router->DiscardOutboundFor(pk);
    return;
  }

  udap::Debug("rc verified");

  // refresh valid routers RC value if it's there
  auto v = router->validRouters.find(pk);
  if(v != router->validRouters.end())
  {
    // free previous RC members
    udap_rc_free(&v->second);
  }
  router->validRouters[pk] = job->rc;

  // TODO: update nodedb here (?)

  // track valid router in dht
  udap_dht_put_peer(router->dht, &router->validRouters[pk]);

  // this was an outbound establish job
  if(ctx->establish_job->session)
  {
    auto session = ctx->establish_job->session;
    router->FlushOutboundFor(pk, session->get_parent(session));
    // this frees the job
    router->pendingEstablishJobs.erase(pk);
  }
}

void
udap_router::handle_router_ticker(void *user, uint64_t orig, uint64_t left)
{
  if(left)
    return;
  udap_router *self  = static_cast< udap_router * >(user);
  self->ticker_job_id = 0;
  self->Tick();
  self->ScheduleTicker(orig);
}

void
udap_router::HandleExploritoryPathBuildStarted(udap_pathbuild_job *job)
{
  delete job;
}

void
udap_router::Tick()
{
  udap::Debug("tick router");
  paths.ExpirePaths();
  // TODO: don't do this if we have enough paths already
  if(inboundLinks.size() == 0)
  {
    auto N = udap_nodedb_num_loaded(nodedb);
    if(N > 2)
    {
      paths.BuildPaths();
    }
    else
    {
      udap::Warn("not enough nodes known to build exploritory paths, have ", N,
                  " nodes");
    }
  }
  udap_link_session_iter iter;
  iter.user  = this;
  iter.visit = &send_padded_message;
  if(sendPadding)
  {
    outboundLink->iter_sessions(outboundLink, iter);
  }
}

bool
udap_router::send_padded_message(udap_link_session_iter *itr,
                                  udap_link_session *peer)
{
  udap_router *self = static_cast< udap_router * >(itr->user);
  udap::RouterID remote;
  remote = &peer->get_remote_router(peer)->pubkey[0];
  udap::DiscardMessage msg(2000);

  udap_buffer_t buf =
      udap::StackBuffer< decltype(linkmsg_buffer) >(self->linkmsg_buffer);

  if(!msg.BEncode(&buf))
    return false;

  buf.sz  = buf.cur - buf.base;
  buf.cur = buf.base;

  for(size_t idx = 0; idx < 5; ++idx)
  {
    peer->sendto(peer, buf);
  }
  return true;
}

void
udap_router::SendTo(udap::RouterID remote, const udap::ILinkMessage *msg,
                     udap_link *link)
{
  udap_buffer_t buf =
      udap::StackBuffer< decltype(linkmsg_buffer) >(linkmsg_buffer);

  if(!msg->BEncode(&buf))
  {
    udap::Warn("failed to encode outbound message, buffer size left: ",
                udap_buffer_size_left(buf));
    return;
  }
  // set size of message
  buf.sz  = buf.cur - buf.base;
  buf.cur = buf.base;
  if(link)
  {
    link->sendto(link, remote, buf);
    return;
  }
  bool sent = outboundLink->sendto(outboundLink, remote, buf);
  if(!sent)
  {
    for(auto link : inboundLinks)
    {
      if(!sent)
      {
        sent = link->sendto(link, remote, buf);
      }
    }
  }
}

void
udap_router::ScheduleTicker(uint64_t ms)
{
  ticker_job_id =
      udap_logic_call_later(logic, {ms, this, &handle_router_ticker});
}

void
udap_router::SessionClosed(const udap::RouterID &remote)
{
  // remove from valid routers and dht if it's a valid router
  auto itr = validRouters.find(remote);
  if(itr == validRouters.end())
    return;

  udap_dht_remove_peer(dht, remote);
  udap_rc_free(&itr->second);
  validRouters.erase(itr);
}

void
udap_router::FlushOutboundFor(const udap::RouterID &remote,
                               udap_link *chosen)
{
  udap::Debug("Flush outbound for ", remote);
  auto itr = outboundMesssageQueue.find(remote);
  if(itr == outboundMesssageQueue.end())
  {
    return;
  }
  while(itr->second.size())
  {
    auto buf = udap::StackBuffer< decltype(linkmsg_buffer) >(linkmsg_buffer);

    auto &msg = itr->second.front();

    if(!msg->BEncode(&buf))
    {
      udap::Warn("failed to encode outbound message, buffer size left: ",
                  udap_buffer_size_left(buf));
      delete msg;
      itr->second.pop();
      continue;
    }
    // set size of message
    buf.sz  = buf.cur - buf.base;
    buf.cur = buf.base;
    if(!chosen->sendto(chosen, remote, buf))
      udap::Warn("failed to send outboud message to ", remote, " via ",
                  chosen->name());

    delete msg;
    itr->second.pop();
  }
}

void
udap_router::on_try_connect_result(udap_link_establish_job *job)
{
  udap_router *router = static_cast< udap_router * >(job->user);
  if(job->session)
  {
    auto session = job->session;
    router->async_verify_RC(session, false, job);
    return;
  }
  udap::PubKey pk = job->pubkey;
  if(job->retries > 0)
  {
    job->retries--;
    job->timeout *= 3;
    job->timeout /= 2;
    udap::Info("session not established with ", pk, " relaxing timeout to ",
                job->timeout);
    // exponential backoff
    udap_logic_call_later(
        router->logic, {job->timeout, job, &udap_router::connect_job_retry});
  }
  else
  {
    udap::Warn("failed to connect to ", pk, " dropping all pending messages");
    router->DiscardOutboundFor(pk);
    router->pendingEstablishJobs.erase(pk);
  }
}

void
udap_router::DiscardOutboundFor(const udap::RouterID &remote)
{
  auto &queue = outboundMesssageQueue[remote];
  while(queue.size())
  {
    delete queue.front();
    queue.pop();
  }
  outboundMesssageQueue.erase(remote);
}

void
udap_router::async_verify_RC(udap_link_session *session,
                              bool isExpectingClient,
                              udap_link_establish_job *establish_job)
{
  udap_async_verify_rc *job = new udap_async_verify_rc;
  job->user  = new udap::async_verify_context{this, establish_job};
  job->rc    = {};
  job->valid = false;
  job->hook  = nullptr;

  job->nodedb = nodedb;
  job->logic  = logic;
  // job->crypto = &crypto; // we already have this
  job->cryptoworker = tp;
  job->diskworker   = disk;

  udap_rc_copy(&job->rc, session->get_remote_router(session));
  if(isExpectingClient)
    job->hook = &udap_router::on_verify_client_rc;
  else
    job->hook = &udap_router::on_verify_server_rc;

  udap_nodedb_async_verify(job);
}

void
udap_router::Run()
{
  // zero out router contact
  udap::Zero(&rc, sizeof(udap_rc));
  // fill our address list
  rc.addrs = udap_ai_list_new();
  for(auto link : inboundLinks)
  {
    udap_ai addr;
    link->get_our_address(link, &addr);
    udap_ai_list_pushback(rc.addrs, &addr);
  };
  // set public encryption key
  udap_rc_set_pubenckey(&rc, udap::seckey_topublic(encryption));

  char ftmp[68]      = {0};
  const char *hexKey = udap::HexEncode< udap::PubKey, decltype(ftmp) >(
      udap::seckey_topublic(encryption), ftmp);
  udap::Info("Your Encryption pubkey ", hexKey);
  // set public signing key
  udap_rc_set_pubsigkey(&rc, udap::seckey_topublic(identity));
  hexKey = udap::HexEncode< udap::PubKey, decltype(ftmp) >(
      udap::seckey_topublic(identity), ftmp);
  udap::Info("Your Identity pubkey ", hexKey);

  udap_rc_sign(&crypto, identity, &rc);

  if(!SaveRC())
  {
    return;
  }

  udap::Debug("starting outbound link");
  if(!outboundLink->start_link(outboundLink, logic))
  {
    udap::Warn("outbound link failed to start");
  }

  int IBLinksStarted = 0;

  // start links
  for(auto link : inboundLinks)
  {
    if(link->start_link(link, logic))
    {
      udap::Debug("Link ", link->name(), " started");
      IBLinksStarted++;
    }
    else
      udap::Warn("Link ", link->name(), " failed to start");
  }

  if(IBLinksStarted > 0)
  {
    // initialize as service node
    InitServiceNode();
    // immediate connect all for service node
    uint64_t delay = rand() % 100;
    udap_logic_call_later(logic, {delay, this, &ConnectAll});
    // udap_logic_call_later(logic, {static_cast<uint64_t>(delay), this,
    // &ConnectAll});
  }
  else
  {
    // delayed connect all for clients
    uint64_t delay = ((rand() % 10) * 500) + 1000;
    udap_logic_call_later(logic, {delay, this, &ConnectAll});
    // udap_logic_call_later(logic, {static_cast<uint64_t>(delay), this,
    // &ConnectAll});
  }

  udap::PubKey ourPubkey = pubkey();
  udap::Info("starting dht context as ", ourPubkey);
  udap_dht_context_start(dht, ourPubkey);

  ScheduleTicker(1000);
}

void
udap_router::InitServiceNode()
{
  udap::Info("accepting transit traffic");
  paths.AllowTransit();
  udap_dht_allow_transit(dht);
}

void
udap_router::ConnectAll(void *user, uint64_t orig, uint64_t left)
{
  if(left)
    return;
  udap_router *self = static_cast< udap_router * >(user);
  for(const auto &itr : self->connect)
  {
    udap::Info("connecting to node ", itr.first);
    self->try_connect(itr.second);
  }
}
bool
udap_router::InitOutboundLink()
{
  if(outboundLink)
    return true;
  auto link = new udap_link;
  udap::Zero(link, sizeof(udap_link));

  udap_iwp_args args = {
      .crypto       = &crypto,
      .logic        = logic,
      .cryptoworker = tp,
      .router       = this,
      .keyfile      = transport_keyfile.c_str(),
  };
  auto afs = {AF_INET, AF_INET6};
  iwp_link_init(link, args);
  if(udap_link_initialized(link))
  {
    udap::Info("outbound link initialized");
    for(auto af : afs)
    {
      if(link->configure(link, netloop, "*", af, 0))
      {
        outboundLink = link;
        udap::Info("outbound link ready");
        return true;
      }
    }
  }
  delete link;
  udap::Error("failed to initialize outbound link");
  return false;
}

bool
udap_router::HasPendingConnectJob(const udap::RouterID &remote)
{
  return pendingEstablishJobs.find(remote) != pendingEstablishJobs.end();
}

extern "C" {
struct udap_router *
udap_init_router(struct udap_threadpool *tp, struct udap_ev_loop *netloop,
                  struct udap_logic *logic)
{
  udap_router *router = new udap_router();
  if(router)
  {
    router->netloop = netloop;
    router->tp      = tp;
    router->logic   = logic;
    // TODO: make disk io threadpool count configurable
#ifdef TESTNET
    router->disk = tp;
#else
    router->disk = udap_init_threadpool(1, "udap-diskio");
#endif
    udap_crypto_libsodium_init(&router->crypto);
  }
  return router;
}

bool
udap_configure_router(struct udap_router *router, struct udap_config *conf)
{
  udap_config_iterator iter;
  iter.user  = router;
  iter.visit = udap::router_iter_config;
  udap_config_iter(conf, &iter);
  if(!router->InitOutboundLink())
    return false;
  if(!router->Ready())
  {
    return false;
  }
  return router->EnsureIdentity();
}

void
udap_run_router(struct udap_router *router, struct udap_nodedb *nodedb)
{
  router->nodedb = nodedb;
  router->Run();
}

bool
udap_router_try_connect(struct udap_router *router, struct udap_rc *remote,
                         uint16_t numretries)
{
  // do  we already have a pending job for this remote?
  if(router->HasPendingConnectJob(remote->pubkey))
    return false;
  // try first address only
  udap_ai addr;
  if(udap_ai_list_index(remote->addrs, 0, &addr))
  {
    auto link = router->outboundLink;
    auto itr  = router->pendingEstablishJobs.emplace(
        std::make_pair(remote->pubkey, udap_link_establish_job()));
    auto job = &itr.first->second;
    udap_ai_copy(&job->ai, &addr);
    memcpy(job->pubkey, remote->pubkey, PUBKEYSIZE);
    job->retries = numretries;
    job->timeout = 10000;
    job->result  = &udap_router::on_try_connect_result;
    // give router as user pointer
    job->user = router;
    // try establishing
    link->try_establish(link, job);
    return true;
  }
  return false;
}

void
udap_rc_clear(struct udap_rc *rc)
{
  // zero out router contact
  udap::Zero(rc, sizeof(udap_rc));
}

void
udap_rc_set_pubenckey(struct udap_rc *rc, const uint8_t *pubenckey)
{
  // set public encryption key
  memcpy(rc->enckey, pubenckey, PUBKEYSIZE);
}

void
udap_rc_set_pubsigkey(struct udap_rc *rc, const uint8_t *pubsigkey)
{
  // set public signing key
  memcpy(rc->pubkey, pubsigkey, PUBKEYSIZE);
}

void
udap_rc_set_pubkey(struct udap_rc *rc, const uint8_t *pubenckey,
                    const uint8_t *pubsigkey)
{
  // set public encryption key
  udap_rc_set_pubenckey(rc, pubenckey);
  // set public signing key
  udap_rc_set_pubsigkey(rc, pubsigkey);
}

struct udap_rc *
udap_rc_read(const char *fpath)
{
  fs::path our_rc_file(fpath);
  std::error_code ec;
  if(!fs::exists(our_rc_file, ec))
  {
    printf("File[%s] not found\n", fpath);
    return 0;
  }
  std::ifstream f(our_rc_file, std::ios::binary);
  if(!f.is_open())
  {
    printf("Can't open file [%s]\n", fpath);
    return 0;
  }
  byte_t tmp[MAX_RC_SIZE];
  udap_buffer_t buf = udap::StackBuffer< decltype(tmp) >(tmp);
  f.seekg(0, std::ios::end);
  size_t sz = f.tellg();
  f.seekg(0, std::ios::beg);

  if(sz > buf.sz)
    return 0;

  f.read((char *)buf.base, sz);
  // printf("contents[%s]\n", tmpc);
  udap_rc *rc = new udap_rc;
  udap::Zero(rc, sizeof(udap_rc));
  if(!udap_rc_bdecode(rc, &buf))
  {
    printf("Can't decode [%s]\n", fpath);
    return 0;
  }
  return rc;
}

bool
udap_rc_addr_list_iter(struct udap_ai_list_iter *iter, struct udap_ai *ai)
{
  struct udap_rc *rc = (udap_rc *)iter->user;
  udap_ai_list_pushback(rc->addrs, ai);
  return true;
}

void
udap_rc_set_addrs(struct udap_rc *rc, struct udap_alloc *mem,
                   struct udap_ai_list *addr)
{
  rc->addrs = udap_ai_list_new();
  struct udap_ai_list_iter ai_itr;
  ai_itr.user  = rc;
  ai_itr.visit = &udap_rc_addr_list_iter;
  udap_ai_list_iterate(addr, &ai_itr);
}

bool
udap_rc_write(struct udap_rc *rc, const char *fpath)
{
  fs::path our_rc_file(fpath);
  byte_t tmp[MAX_RC_SIZE];
  auto buf = udap::StackBuffer< decltype(tmp) >(tmp);

  if(udap_rc_bencode(rc, &buf))
  {
    std::ofstream f(our_rc_file, std::ios::binary);
    if(f.is_open())
    {
      f.write((char *)buf.base, buf.cur - buf.base);
      return true;
    }
  }
  return false;
}

void
udap_rc_sign(udap_crypto *crypto, const byte_t *seckey, struct udap_rc *rc)
{
  byte_t buf[MAX_RC_SIZE];
  auto signbuf = udap::StackBuffer< decltype(buf) >(buf);
  // zero out previous signature
  udap::Zero(rc->signature, sizeof(rc->signature));
  // encode
  if(udap_rc_bencode(rc, &signbuf))
  {
    // sign
    signbuf.sz = signbuf.cur - signbuf.base;
    crypto->sign(rc->signature, seckey, signbuf);
  }
}

void
udap_stop_router(struct udap_router *router)
{
  if(router)
    router->Close();
}

void
udap_router_iterate_links(struct udap_router *router,
                           struct udap_router_link_iter i)
{
  for(auto link : router->inboundLinks)
    if(!i.visit(&i, router, link))
      return;
  i.visit(&i, router, router->outboundLink);
}

void
udap_free_router(struct udap_router **router)
{
  if(*router)
  {
    delete *router;
  }
  *router = nullptr;
}

void
udap_router_override_path_selection(struct udap_router *router,
                                     udap_pathbuilder_select_hop_func func)
{
  if(func)
    router->selectHopFunc = func;
}

bool
udap_findOrCreateIdentity(udap_crypto *crypto, const char *fpath,
                           byte_t *secretkey)
{
  udap::Debug("find or create ", fpath);
  fs::path path(fpath);
  std::error_code ec;
  if(!fs::exists(path, ec))
  {
    udap::Info("generating new identity key");
    crypto->identity_keygen(secretkey);
    std::ofstream f(path, std::ios::binary);
    if(f.is_open())
    {
      f.write((char *)secretkey, SECKEYSIZE);
    }
  }
  std::ifstream f(path, std::ios::binary);
  if(f.is_open())
  {
    f.read((char *)secretkey, SECKEYSIZE);
    return true;
  }
  udap::Info("failed to get identity key");
  return false;
}

}  // end extern C

// C++ ...
bool
udap_findOrCreateEncryption(udap_crypto *crypto, const char *fpath,
                             udap::SecretKey *encryption)
{
  udap::Debug("find or create ", fpath);
  fs::path path(fpath);
  std::error_code ec;
  if(!fs::exists(path, ec))
  {
    udap::Info("generating new encryption key");
    crypto->encryption_keygen(*encryption);
    std::ofstream f(path, std::ios::binary);
    if(f.is_open())
    {
      f.write((char *)encryption, SECKEYSIZE);
    }
  }
  std::ifstream f(path, std::ios::binary);
  if(f.is_open())
  {
    f.read((char *)encryption, SECKEYSIZE);
    return true;
  }
  udap::Info("failed to get encryption key");
  return false;
}

namespace udap
{
  void
  router_iter_config(udap_config_iterator *iter, const char *section,
                     const char *key, const char *val)
  {
    udap_router *self = static_cast< udap_router * >(iter->user);
    int af;
    uint16_t proto;
    if(StrEq(val, "eth"))
    {
#ifdef AF_LINK
      af = AF_LINK;
#endif
#ifdef AF_PACKET
      af = AF_PACKET;
#endif
      proto = UDAP_ETH_PROTO;
    }
    else
    {
      // try IPv4 first
      af    = AF_INET;
      proto = std::atoi(val);
    }

    struct udap_link *link = nullptr;
    if(StrEq(section, "bind"))
    {
      if(!StrEq(key, "*"))
      {
        link = new udap_link;
        udap::Zero(link, sizeof(udap_link));

        udap_iwp_args args = {
            .crypto       = &self->crypto,
            .logic        = self->logic,
            .cryptoworker = self->tp,
            .router       = self,
            .keyfile      = self->transport_keyfile.c_str(),
        };
        iwp_link_init(link, args);
        if(udap_link_initialized(link))
        {
          udap::Info("link ", key, " initialized");
          if(link->configure(link, self->netloop, key, af, proto))
          {
            self->AddInboundLink(link);
            return;
          }
          if(af == AF_INET6)
          {
            // we failed to configure IPv6
            // try IPv4
            udap::Info("link ", key, " failed to configure IPv6, trying IPv4");
            af = AF_INET;
            if(link->configure(link, self->netloop, key, af, proto))
            {
              self->AddInboundLink(link);
              return;
            }
          }
        }
      }
      udap::Error("link ", key, " failed to configure");
    }
    else if(StrEq(section, "connect"))
    {
      self->connect[key] = val;
    }
    else if(StrEq(section, "router"))
    {
      if(StrEq(key, "encryption-privkey"))
      {
        self->encryption_keyfile = val;
      }
      if(StrEq(key, "contact-file"))
      {
        self->our_rc_file = val;
      }
      if(StrEq(key, "transport-privkey"))
      {
        self->transport_keyfile = val;
      }
      if(StrEq(key, "ident-privkey"))
      {
        self->ident_keyfile = val;
      }
    }
  }

}  // namespace udap
