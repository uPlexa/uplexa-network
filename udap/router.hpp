#ifndef UDAP_ROUTER_HPP
#define UDAP_ROUTER_HPP
#include <udap/dht.h>
#include <udap/link.h>
#include <udap/nodedb.h>
#include <udap/router.h>
#include <udap/router_contact.h>
#include <udap/path.hpp>

#include <functional>
#include <list>
#include <map>
#include <unordered_map>

#include <udap/dht.hpp>
#include <udap/link_message.hpp>
#include <udap/routing/handler.hpp>

#include "crypto.hpp"
#include "fs.hpp"
#include "mem.hpp"

namespace udap
{
  struct try_connect_ctx
  {
    udap_router *router = nullptr;
    udap_ai addr;
  };

  // forward declare
  namespace path
  {
    struct TransitHop;
  }
}  // namespace udap

/// c++
bool
udap_findOrCreateEncryption(udap_crypto *crypto, const char *fpath,
                             udap::SecretKey *encryption);

struct udap_router
{
  bool ready;
  // transient iwp encryption key
  fs::path transport_keyfile = "transport.key";

  // nodes to connect to on startup
  std::map< std::string, fs::path > connect;

  // long term identity key
  fs::path ident_keyfile = "identity.key";

  fs::path encryption_keyfile = "encryption.key";

  // path to write our self signed rc to
  fs::path our_rc_file = "rc.signed";

  // our router contact
  udap_rc rc;

  udap_ev_loop *netloop;
  udap_threadpool *tp;
  udap_logic *logic;
  udap_crypto crypto;
  udap::path::PathContext paths;
  udap::SecretKey identity;
  udap::SecretKey encryption;
  udap_threadpool *disk;
  udap_dht_context *dht = nullptr;

  udap_nodedb *nodedb;

  // buffer for serializing link messages
  byte_t linkmsg_buffer[MAX_LINK_MSG_SIZE];

  // should we be sending padded messages every interval?
  bool sendPadding = false;

  uint32_t ticker_job_id = 0;

  udap::InboundMessageParser inbound_link_msg_parser;
  udap::routing::InboundMessageParser inbound_routing_msg_parser;

  udap_pathbuilder_select_hop_func selectHopFunc = nullptr;
  udap_pathbuilder_context *explorePool          = nullptr;

  udap_link *outboundLink = nullptr;
  std::list< udap_link * > inboundLinks;

  typedef std::queue< const udap::ILinkMessage * > MessageQueue;

  /// outbound message queue
  std::map< udap::RouterID, MessageQueue > outboundMesssageQueue;

  /// uplexa verified routers
  std::map< udap::RouterID, udap_rc > validRouters;

  std::map< udap::PubKey, udap_link_establish_job > pendingEstablishJobs;

  udap_router();
  virtual ~udap_router();

  bool
  HandleRecvLinkMessage(struct udap_link_session *from, udap_buffer_t msg);

  void
  AddInboundLink(struct udap_link *link);

  bool
  InitOutboundLink();

  /// initialize us as a service node
  void
  InitServiceNode();

  void
  Close();

  bool
  Ready();

  void
  Run();

  static void
  ConnectAll(void *user, uint64_t orig, uint64_t left);

  bool
  EnsureIdentity();

  bool
  EnsureEncryptionKey();

  bool
  SaveRC();

  const byte_t *
  pubkey() const
  {
    return udap::seckey_topublic(identity);
  }

  bool
  HasPendingConnectJob(const udap::RouterID &remote);

  void
  try_connect(fs::path rcfile);

  /// send to remote router or queue for sending
  /// returns false on overflow
  /// returns true on successful queue
  /// NOT threadsafe
  /// MUST be called in the logic thread
  bool
  SendToOrQueue(const udap::RouterID &remote, const udap::ILinkMessage *msg);

  /// sendto or drop
  void
  SendTo(udap::RouterID remote, const udap::ILinkMessage *msg,
         udap_link *chosen = nullptr);

  /// manually flush outbound message queue for just 1 router
  void
  FlushOutboundFor(const udap::RouterID &remote, udap_link *chosen);

  /// manually discard all pending messages to remote router
  void
  DiscardOutboundFor(const udap::RouterID &remote);

  /// flush outbound message queue
  void
  FlushOutbound();

  /// called by link when a remote session is expunged
  void
  SessionClosed(const udap::RouterID &remote);

  /// call internal router ticker
  void
  Tick();

  /// schedule ticker to call i ms from now
  void
  ScheduleTicker(uint64_t i = 1000);

  void
  async_verify_RC(udap_link_session *session, bool isExpectingClient,
                  udap_link_establish_job *job = nullptr);

  static bool
  iter_try_connect(udap_router_link_iter *i, udap_router *router,
                   udap_link *l);

  static void
  on_try_connect_result(udap_link_establish_job *job);

  static void
  connect_job_retry(void *user, uint64_t orig, uint64_t left);

  static void
  on_verify_client_rc(udap_async_verify_rc *context);

  static void
  on_verify_server_rc(udap_async_verify_rc *context);

  static void
  handle_router_ticker(void *user, uint64_t orig, uint64_t left);

  static bool
  send_padded_message(struct udap_link_session_iter *itr,
                      struct udap_link_session *peer);

  static void
  HandleAsyncLoadRCForSendTo(udap_async_load_rc *async);

  static void
  HandleDHTLookupForSendTo(udap_router_lookup_job *job);

  static void
  HandleExploritoryPathBuildStarted(udap_pathbuild_job *job);
};

#endif
