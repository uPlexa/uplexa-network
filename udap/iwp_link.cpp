#include <udap/crypto_async.h>
#include <udap/iwp.h>
#include <udap/net.h>
#include <udap/time.h>
#include <udap/crypto.hpp>
#include "address_info.hpp"
#include "codel.hpp"
#include "link/encoder.hpp"

#include <sodium/crypto_sign_ed25519.h>

#include <algorithm>
#include <bitset>
#include <cassert>
#include <fstream>
#include <list>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <unordered_map>
#include <vector>

#include "buffer.hpp"
#include "fs.hpp"
#include "logger.hpp"
#include "mem.hpp"
#include "net.hpp"
#include "router.hpp"
#include "str.hpp"

namespace iwp
{
  // session activity timeout is 10s
  constexpr udap_time_t SESSION_TIMEOUT = 10000;

  constexpr size_t MAX_PAD = 128;

  enum msgtype
  {
    eALIV = 0x00,
    eXMIT = 0x01,
    eACKS = 0x02,
    eFRAG = 0x03
  };

  struct sendbuf_t
  {
    sendbuf_t(size_t s) : sz(s)
    {
      buf = new byte_t[s];
    }

    ~sendbuf_t()
    {
      delete[] buf;
    }

    byte_t *buf;
    size_t sz;

    size_t
    size() const
    {
      return sz;
    }

    byte_t *
    data()
    {
      return buf;
    }
  };

  enum header_flag
  {
    eSessionInvalidated = (1 << 0),
    eHighPacketDrop     = (1 << 1),
    eHighMTUDetected    = (1 << 2),
    eProtoUpgrade       = (1 << 3)
  };

  /** plaintext frame header */
  struct frame_header
  {
    byte_t *ptr;

    frame_header(byte_t *buf) : ptr(buf)
    {
    }

    byte_t *
    data()
    {
      return ptr + 6;
    }

    uint8_t &
    version()
    {
      return ptr[0];
    }

    uint8_t &
    msgtype()
    {
      return ptr[1];
    }

    uint16_t
    size() const
    {
      uint16_t sz;
      memcpy(&sz, ptr + 2, 2);
      return sz;
    }

    void
    setsize(uint16_t sz)
    {
      memcpy(ptr + 2, &sz, 2);
    }

    uint8_t &
    flags()
    {
      return ptr[5];
    }

    void
    setflag(header_flag f)
    {
      ptr[5] |= f;
    }
  };

  byte_t *
  init_sendbuf(sendbuf_t *buf, msgtype t, uint16_t sz, uint8_t flags)
  {
    frame_header hdr(buf->data());
    hdr.version() = 0;
    hdr.msgtype() = t;
    hdr.setsize(sz);
    buf->data()[4] = 0;
    buf->data()[5] = flags;
    return hdr.data();
  }

  /** xmit header */
  struct xmit
  {
    byte_t buffer[48];

    xmit() = default;

    xmit(byte_t *ptr)
    {
      memcpy(buffer, ptr, sizeof(buffer));
    }

    xmit(const xmit &other)
    {
      memcpy(buffer, other.buffer, sizeof(buffer));
    }

    void
    set_info(const byte_t *hash, uint64_t id, uint16_t fragsz, uint16_t lastsz,
             uint8_t numfrags, uint8_t flags = 0x01)
    {
      // big endian assumed
      // TODO: implement little endian
      memcpy(buffer, hash, 32);
      memcpy(buffer + 32, &id, 8);
      memcpy(buffer + 40, &fragsz, 2);
      memcpy(buffer + 42, &lastsz, 2);
      buffer[44] = 0;
      buffer[45] = 0;
      buffer[46] = numfrags;
      buffer[47] = flags;
    }

    const byte_t *
    hash() const
    {
      return &buffer[0];
    }

    uint64_t
    msgid() const
    {
      // big endian assumed
      // TODO: implement little endian
      const byte_t *start   = buffer + 32;
      const uint64_t *msgid = (const uint64_t *)start;
      return *msgid;
    }

    // size of each full fragment
    uint16_t
    fragsize() const
    {
      // big endian assumed
      // TODO: implement little endian
      const byte_t *start    = buffer + 40;
      const uint16_t *fragsz = (uint16_t *)start;
      return *fragsz;
    }

    // number of full fragments
    uint8_t
    numfrags() const
    {
      return buffer[46];
    }

    // size of the entire message
    size_t
    totalsize() const
    {
      return (fragsize() * numfrags()) + lastfrag();
    }

    // size of the last fragment
    uint16_t
    lastfrag() const
    {
      // big endian assumed
      // TODO: implement little endian
      const byte_t *start    = buffer + 42;
      const uint16_t *lastsz = (uint16_t *)start;
      return *lastsz;
    }

    uint8_t
    flags()
    {
      return buffer[47];
    }
  };

  // forward declare
  struct session;
  struct server;

  struct transit_message
  {
    xmit msginfo;
    std::bitset< 32 > status = {};

    typedef std::vector< byte_t > fragment_t;

    std::unordered_map< byte_t, fragment_t > frags;
    fragment_t lastfrag;

    void
    clear()
    {
      frags.clear();
      lastfrag.clear();
    }

    // calculate acked bitmask
    uint32_t
    get_bitmask() const
    {
      uint32_t bitmask = 0;
      uint8_t idx      = 0;
      while(idx < 32)
      {
        bitmask |= (status.test(idx) ? (1 << idx) : 0);
        ++idx;
      }
      return bitmask;
    }

    // outbound
    transit_message(udap_buffer_t buf, const byte_t *hash, uint64_t id,
                    uint16_t mtu = 1024)
    {
      put_message(buf, hash, id, mtu);
    }

    // inbound
    transit_message(const xmit &x) : msginfo(x)
    {
      byte_t fragidx    = 0;
      uint16_t fragsize = x.fragsize();
      while(fragidx < x.numfrags())
      {
        frags[fragidx].resize(fragsize);
        ++fragidx;
      }
      status.reset();
    }

    /// ack packets based off a bitmask
    void
    ack(uint32_t bitmask)
    {
      uint8_t idx = 0;
      while(idx < 32)
      {
        if(bitmask & (1 << idx))
        {
          status.set(idx);
        }
        ++idx;
      }
    }

    bool
    should_send_ack() const
    {
      if(msginfo.numfrags() == 0)
        return true;
      return status.count() % (1 + (msginfo.numfrags() / 2)) == 0;
    }

    bool
    completed() const
    {
      for(byte_t idx = 0; idx < msginfo.numfrags(); ++idx)
      {
        if(!status.test(idx))
          return false;
      }
      return true;
    }

    template < typename T >
    void
    generate_xmit(T &queue, byte_t flags = 0)
    {
      uint16_t sz = lastfrag.size() + sizeof(msginfo.buffer);
      queue.push(new sendbuf_t(sz + 6));
      auto body_ptr = init_sendbuf(queue.back(), eXMIT, sz, flags);
      memcpy(body_ptr, msginfo.buffer, sizeof(msginfo.buffer));
      body_ptr += sizeof(msginfo.buffer);
      memcpy(body_ptr, lastfrag.data(), lastfrag.size());
    }

    template < typename T >
    void
    retransmit_frags(T &queue, byte_t flags = 0)
    {
      auto msgid    = msginfo.msgid();
      auto fragsize = msginfo.fragsize();
      for(auto &frag : frags)
      {
        if(status.test(frag.first))
          continue;
        uint16_t sz = 9 + fragsize;
        queue.push(new sendbuf_t(sz + 6));
        auto body_ptr = init_sendbuf(queue.back(), eFRAG, sz, flags);
        // TODO: assumes big endian
        memcpy(body_ptr, &msgid, 8);
        body_ptr[8] = frag.first;
        memcpy(body_ptr + 9, frag.second.data(), fragsize);
      }
    }

    bool
    reassemble(std::vector< byte_t > &buffer)
    {
      auto total = msginfo.totalsize();
      buffer.resize(total);
      auto fragsz = msginfo.fragsize();
      auto ptr    = &buffer[0];
      for(byte_t idx = 0; idx < msginfo.numfrags(); ++idx)
      {
        if(!status.test(idx))
          return false;
        memcpy(ptr, frags[idx].data(), fragsz);
        ptr += fragsz;
      }
      memcpy(ptr, lastfrag.data(), lastfrag.size());
      return true;
    }

    void
    put_message(udap_buffer_t buf, const byte_t *hash, uint64_t id,
                uint16_t mtu = 1024)
    {
      status.reset();
      uint8_t fragid    = 0;
      uint16_t fragsize = mtu;
      size_t left       = buf.sz;
      while(left > fragsize)
      {
        auto &frag = frags[fragid];
        frag.resize(fragsize);
        memcpy(frag.data(), buf.cur, fragsize);
        buf.cur += fragsize;
        fragid++;
        left -= fragsize;
      }
      uint16_t lastfrag = buf.sz - (buf.cur - buf.base);
      // set info for xmit
      msginfo.set_info(hash, id, fragsize, lastfrag, fragid);
      put_lastfrag(buf.cur, lastfrag);
    }

    void
    put_lastfrag(byte_t *buf, size_t sz)
    {
      lastfrag.resize(sz);
      memcpy(lastfrag.data(), buf, sz);
    }

    bool
    put_frag(byte_t fragno, byte_t *buf)
    {
      auto itr = frags.find(fragno);
      if(itr == frags.end())
        return false;
      memcpy(itr->second.data(), buf, msginfo.fragsize());
      status.set(fragno);
      return true;
    }
  };

  struct frame_state
  {
    byte_t rxflags         = 0;
    byte_t txflags         = 0;
    uint64_t rxids         = 0;
    uint64_t txids         = 0;
    udap_time_t lastEvent = 0;
    std::unordered_map< uint64_t, transit_message * > rx;
    std::unordered_map< uint64_t, transit_message * > tx;

    typedef std::queue< sendbuf_t * > sendqueue_t;

    udap_router *router       = nullptr;
    udap_link_session *parent = nullptr;

    sendqueue_t sendqueue;

    /// return true if both sides have the same state flags
    bool
    flags_agree(byte_t flags) const
    {
      return ((rxflags & flags) & (txflags & flags)) == flags;
    }

    void
    clear()
    {
      auto _rx = rx;
      auto _tx = tx;
      for(auto &item : _rx)
        delete item.second;
      for(auto &item : _tx)
        delete item.second;
      rx.clear();
      tx.clear();
    }

    bool
    inbound_frame_complete(uint64_t id);

    void
    push_ackfor(uint64_t id, uint32_t bitmask)
    {
      udap::Debug("ACK for msgid=", id, " mask=", bitmask);
      sendqueue.push(new sendbuf_t(12 + 6));
      auto body_ptr = init_sendbuf(sendqueue.back(), eACKS, 12, txflags);
      // TODO: this assumes big endian
      memcpy(body_ptr, &id, 8);
      memcpy(body_ptr + 8, &bitmask, 4);
    }

    bool
    got_xmit(frame_header hdr, size_t sz)
    {
      if(hdr.size() > sz)
      {
        // overflow
        udap::Warn("invalid XMIT frame size ", hdr.size(), " > ", sz);
        return false;
      }
      sz = hdr.size();

      // extract xmit data
      xmit x(hdr.data());

      const auto bufsz = sizeof(x.buffer);

      if(sz - bufsz < x.lastfrag())
      {
        // bad size of last fragment
        udap::Warn("XMIT frag size missmatch ", sz - bufsz, " < ",
                    x.lastfrag());
        return false;
      }

      // check LSB set on flags
      if(x.flags() & 0x01)
      {
        auto id  = x.msgid();
        auto itr = rx.find(id);
        if(itr == rx.end())
        {
          auto msg = new transit_message(x);
          rx[id]   = msg;
          udap::Debug("got message XMIT with ", (int)x.numfrags(),
                       " fragments");
          // inserted, put last fragment
          msg->put_lastfrag(hdr.data() + sizeof(x.buffer), x.lastfrag());
          push_ackfor(id, 0);
          if(x.numfrags() == 0)
          {
            return inbound_frame_complete(id);
          }
          return true;
        }
        else
          udap::Warn("duplicate XMIT msgid=", x.msgid());
      }
      else
        udap::Warn("LSB not set on flags");
      return false;
    }

    void
    alive()
    {
      lastEvent = udap_time_now_ms();
    }

    bool
    got_frag(frame_header hdr, size_t sz)
    {
      if(hdr.size() > sz)
      {
        // overflow
        udap::Warn("invalid FRAG frame size ", hdr.size(), " > ", sz);
        return false;
      }
      sz = hdr.size();

      if(sz <= 9)
      {
        // underflow
        udap::Warn("invalid FRAG frame size ", sz, " <= 9");
        return false;
      }

      uint64_t msgid;
      byte_t fragno;
      // assumes big endian
      // TODO: implement little endian
      memcpy(&msgid, hdr.data(), 8);
      memcpy(&fragno, hdr.data() + 8, 1);

      auto itr = rx.find(msgid);
      if(itr == rx.end())
      {
        udap::Warn("no such RX fragment, msgid=", msgid);
        return true;
      }
      auto fragsize = itr->second->msginfo.fragsize();
      if(fragsize != sz - 9)
      {
        udap::Warn("RX fragment size missmatch ", fragsize, " != ", sz - 9);
        return false;
      }
      udap::Debug("RX got fragment ", (int)fragno, " msgid=", msgid);
      if(!itr->second->put_frag(fragno, hdr.data() + 9))
      {
        udap::Warn("inbound message does not have fragment msgid=", msgid,
                    " fragno=", (int)fragno);
        return false;
      }
      auto mask = itr->second->get_bitmask();
      if(itr->second->completed())
      {
        push_ackfor(msgid, mask);
        return inbound_frame_complete(msgid);
      }
      else if(itr->second->should_send_ack())
      {
        push_ackfor(msgid, mask);
      }
      return true;
    }

    bool
    got_acks(frame_header hdr, size_t sz);

    // queue new outbound message
    void
    queue_tx(uint64_t id, transit_message *msg)
    {
      tx.insert(std::make_pair(id, msg));
      msg->generate_xmit(sendqueue, txflags);
    }

    void
    retransmit()
    {
      for(auto &item : tx)
      {
        item.second->retransmit_frags(sendqueue, txflags);
      }
    }

    // get next frame to encrypt and transmit
    bool
    next_frame(udap_buffer_t *buf)
    {
      auto left = sendqueue.size();
      udap::Debug("next frame, ", left, " frames left in send queue");
      if(left)
      {
        sendbuf_t *send = sendqueue.front();
        buf->base       = send->data();
        buf->cur        = send->data();
        buf->sz         = send->size();
        return true;
      }
      return false;
    }

    void
    pop_next_frame()
    {
      sendbuf_t *buf = sendqueue.front();
      sendqueue.pop();
      delete buf;
    }

    bool
    process(byte_t *buf, size_t sz)
    {
      frame_header hdr(buf);
      if(hdr.flags() & eSessionInvalidated)
      {
        rxflags |= eSessionInvalidated;
      }
      switch(hdr.msgtype())
      {
        case eALIV:
          if(rxflags & eSessionInvalidated)
          {
            txflags |= eSessionInvalidated;
          }
          return true;
        case eXMIT:
          return got_xmit(hdr, sz - 6);
        case eACKS:
          return got_acks(hdr, sz - 6);
        case eFRAG:
          return got_frag(hdr, sz - 6);
        default:
          udap::Warn("invalid message header");
          return false;
      }
    }
  };

  /// get the time from a iwp_async_frame
  struct FrameGetTime
  {
    udap_time_t
    operator()(const iwp_async_frame *frame) const
    {
      return frame->created;
    }
  };

  struct FramePutTime
  {
    void
    operator()(iwp_async_frame *frame) const
    {
      frame->created = udap_time_now_ms();
    }
  };

  struct session
  {
    udap_udp_io *udp;
    udap_crypto *crypto;
    udap_async_iwp *iwp;
    udap_logic *logic;

    udap_link_session *parent = nullptr;
    server *serv               = nullptr;

    udap_rc *our_router = nullptr;
    udap_rc remote_router;

    udap::SecretKey eph_seckey;
    udap::PubKey remote;
    udap::SharedSecret sessionkey;

    udap_link_establish_job *establish_job = nullptr;

    /// cached timestamp for frame creation
    udap_time_t now, inboundNow;
    uint32_t establish_job_id = 0;
    uint32_t frames           = 0;
    bool working              = false;

    udap::util::CoDelQueue< iwp_async_frame *, FrameGetTime, FramePutTime >
        outboundFrames;
    /*
    std::mutex m_EncryptedFramesMutex;
    std::queue< iwp_async_frame > encryptedFrames;
    udap::util::CoDelQueue< iwp_async_frame *, FrameGetTime, FramePutTime >
        decryptedFrames;
     */

    uint32_t pump_send_timer_id = 0;
    uint32_t pump_recv_timer_id = 0;

    udap::Addr addr;
    iwp_async_intro intro;
    iwp_async_introack introack;
    iwp_async_session_start start;
    frame_state frame;
    bool started_inbound_codel = false;

    byte_t token[32];
    byte_t workbuf[MAX_PAD + 128];

    enum State
    {
      eInitial,
      eIntroRecv,
      eIntroSent,
      eIntroAckSent,
      eIntroAckRecv,
      eSessionStartSent,
      eLIMSent,
      eEstablished,
      eTimeout
    };

    State state;

    session(udap_udp_io *u, udap_async_iwp *i, udap_crypto *c,
            udap_logic *l, const byte_t *seckey, const udap::Addr &a)
        : udp(u)
        , crypto(c)
        , iwp(i)
        , logic(l)
        , outboundFrames("iwp_outbound")
        //, decryptedFrames("iwp_inbound")
        , addr(a)
        , state(eInitial)
    {
      eph_seckey = seckey;
      udap::Zero(&remote_router, sizeof(udap_rc));
      crypto->randbytes(token, 32);
    }

    ~session()
    {
      udap_rc_free(&remote_router);
      frame.clear();
    }

    static udap_rc *
    get_remote_router(udap_link_session *s)
    {
      session *self = static_cast< session * >(s->impl);
      return &self->remote_router;
    }

    static bool
    sendto(udap_link_session *s, udap_buffer_t msg)
    {
      session *self = static_cast< session * >(s->impl);
      auto id       = self->frame.txids++;
      udap::ShortHash digest;
      self->crypto->shorthash(digest, msg);
      transit_message *m = new transit_message(msg, digest, id);
      self->add_outbound_message(id, m);
      return true;
    }

    void
    add_outbound_message(uint64_t id, transit_message *msg)
    {
      udap::Debug("add outbound message ", id, " of size ",
                   msg->msginfo.totalsize(),
                   " numfrags=", (int)msg->msginfo.numfrags(),
                   " lastfrag=", (int)msg->msginfo.lastfrag());
      frame.queue_tx(id, msg);
      pump();
      PumpCryptoOutbound();
    }

    static void
    handle_invalidate_timer(void *user);

    bool
    CheckRCValid()
    {
      // verify signatuire
      if(!udap_rc_verify_sig(crypto, &remote_router))
        return false;

      auto &list = remote_router.addrs->list;
      if(list.size() == 0)  // the remote node is a client node so accept it
        return true;
      // check if the RC owns a pubkey that we are using
      for(auto &ai : list)
      {
        if(memcmp(ai.enc_key, remote, PUBKEYSIZE) == 0)
          return true;
      }
      return false;
    }

    void
    PumpCryptoOutbound();
    /*
        void
        HandleInboundCodel()
        {
          std::queue< iwp_async_frame * > outq;
          decryptedFrames.Process(outq);
          while(outq.size())
          {
            auto &front = outq.front();
            handle_frame_decrypt(front);
            delete front;
            outq.pop();
          }
          PumpCryptoOutbound();
        }

        static void
        handle_inbound_codel_delayed(void *user, uint64_t orig, uint64_t left)
        {
          if(left)
            return;
          session *self            = static_cast< session * >(user);
          self->pump_recv_timer_id = 0;
          self->HandleInboundCodel();
          self->PumpCodelInbound();
        }

        static void
        handle_start_inbound_codel(void *user)
        {
          session *self = static_cast< session * >(user);
          self->HandleInboundCodel();
          self->PumpCodelInbound();
        }

        void
        StartInboundCodel()
        {
          if(started_inbound_codel)
            return;
          started_inbound_codel = true;
          udap_logic_queue_job(logic, {this, &handle_start_inbound_codel});
        }

        static void
        handle_pump_inbound_codel(void *user)
        {
          session *self = static_cast< session * >(user);
          self->HandleInboundCodel();
        }

        void
        ManualPumpInboundCodel()
        {
          udap_logic_queue_job(logic, {this, &handle_pump_inbound_codel});
        }

        void
        PumpCodelInbound()
        {
          pump_recv_timer_id =
              udap_logic_call_later(logic,
                                     {decryptedFrames.nextTickInterval, this,
                                      &handle_inbound_codel_delayed});
        }
      */
    void
    pump()
    {
      // TODO: in codel the timestamp may cause excssive drop when all the
      // packets have a similar timestamp
      now = udap_time_now_ms();
      udap_buffer_t buf;
      while(frame.next_frame(&buf))
      {
        encrypt_frame_async_send(buf.base, buf.sz);
        frame.pop_next_frame();
      }
    }

    // this is called from net thread
    void
    recv(const void *buf, size_t sz)
    {
      now = udap_time_now_ms();
      switch(state)
      {
        case eInitial:
          // got intro
          on_intro(buf, sz);
          return;
        case eIntroSent:
          // got intro ack
          on_intro_ack(buf, sz);
          return;
        case eIntroAckSent:
          // probably a session start
          on_session_start(buf, sz);
          return;

        case eSessionStartSent:
        case eLIMSent:
        case eEstablished:
          // session is started
          decrypt_frame(buf, sz);
        default:
          // invalid state?
          return;
      }
    }

    static void
    handle_verify_session_start(iwp_async_session_start *s);

    void
    send_LIM()
    {
      udap::Debug("send LIM");
      udap::ShortHash digest;
      // 64 bytes overhead for link message
      byte_t tmp[MAX_RC_SIZE + 64];
      auto buf = udap::StackBuffer< decltype(tmp) >(tmp);
      // return a udap_buffer_t of encoded link message
      if(udap::EncodeLIM(&buf, our_router))
      {
        // rewind message buffer
        buf.sz  = buf.cur - buf.base;
        buf.cur = buf.base;
        // hash message buffer
        crypto->shorthash(digest, buf);
        auto id  = frame.txids++;
        auto msg = new transit_message(buf, digest, id);
        // put into outbound send queue
        add_outbound_message(id, msg);
        // enter state
        EnterState(eLIMSent);
      }
      else
        udap::Error("LIM Encode failed");
    }

    static void
    send_keepalive(void *user);

    // return true if we should be removed
    bool
    Tick(uint64_t now);

    static void
    codel_timer_handler(void *user, uint64_t orig, uint64_t left);

    bool
    IsEstablished()
    {
      return state == eEstablished;
    }

    void
    session_established();

    void
    on_session_start(const void *buf, size_t sz)
    {
      if(sz > sizeof(workbuf))
      {
        udap::Debug("session start too big");
        return;
      }
      // own the buffer
      memcpy(workbuf, buf, sz);
      // verify session start
      start.buf           = workbuf;
      start.sz            = sz;
      start.nonce         = workbuf + 32;
      start.token         = token;
      start.remote_pubkey = remote;
      start.secretkey     = eph_seckey;
      start.sessionkey    = sessionkey;
      start.user          = this;
      start.hook          = &handle_verify_session_start;
      working             = true;
      iwp_call_async_verify_session_start(iwp, &start);
    }

    bool
    timedout(udap_time_t now, udap_time_t timeout = SESSION_TIMEOUT)
    {
      auto diff = now - frame.lastEvent;
      return diff >= timeout;
    }

    static bool
    is_timedout(udap_link_session *s)
    {
      auto now = udap_time_now_ms();
      return static_cast< session * >(s->impl)->timedout(now);
    }

    static void
    handle_session_established(void *user)
    {
      session *impl = static_cast< session * >(user);
      impl->session_established();
    }

    static void
    set_established(udap_link_session *s)
    {
      session *impl = static_cast< session * >(s->impl);
      udap_logic_queue_job(impl->logic, {impl, &handle_session_established});
    }

    static void
    close(udap_link_session *s)
    {
      session *impl = static_cast< session * >(s->impl);
      // set our side invalidated and close async when the other side also marks
      // as session invalidated
      impl->frame.txflags |= eSessionInvalidated;
      // TODO: add timer for session invalidation
      udap_logic_queue_job(impl->logic, {impl, &send_keepalive});
    }

    static void
    handle_verify_introack(iwp_async_introack *introack);

    static void
    handle_generated_session_start(iwp_async_session_start *start)
    {
      session *link = static_cast< session * >(start->user);
      link->working = false;
      if(udap_ev_udp_sendto(link->udp, link->addr, start->buf, start->sz)
         == -1)
        udap::Error("sendto failed");
      link->EnterState(eSessionStartSent);
    }

    bool
    is_invalidated() const
    {
      return frame.flags_agree(eSessionInvalidated);
    }

    void
    session_start()
    {
      size_t w2sz = rand() % MAX_PAD;
      start.buf   = workbuf;
      start.sz    = w2sz + (32 * 3);
      start.nonce = workbuf + 32;
      crypto->randbytes(start.nonce, 32);
      start.token = token;
      memcpy(start.buf + 64, token, 32);
      if(w2sz)
        crypto->randbytes(start.buf + (32 * 3), w2sz);
      start.remote_pubkey = remote;
      start.secretkey     = eph_seckey;
      start.sessionkey    = sessionkey;
      start.user          = this;
      start.hook          = &handle_generated_session_start;
      working             = true;
      iwp_call_async_gen_session_start(iwp, &start);
    }

    static void
    handle_frame_decrypt(iwp_async_frame *frame)
    {
      session *self = static_cast< session * >(frame->user);
      udap::Debug("rx ", frame->sz);
      if(frame->success)
      {
        if(self->frame.process(frame->buf + 64, frame->sz - 64))
        {
          self->frame.alive();
          self->pump();
        }
        else
          udap::Error("invalid frame from ", self->addr);
      }
      else
        udap::Error("decrypt frame fail from ", self->addr);
    }

    void
    decrypt_frame(const void *buf, size_t sz)
    {
      if(sz > 64)
      {
        auto f = alloc_frame(buf, sz);
        /*
        if(iwp_decrypt_frame(f))
        {
          decryptedFrames.Put(f);
          if(state == eEstablished)
          {
            if(pump_recv_timer_id == 0)
              PumpCodelInbound();
          }
          else
            ManualPumpInboundCodel();
        }
        else
          udap::Warn("decrypt frame fail");
       */
        f->hook = &handle_frame_decrypt;
        iwp_call_async_frame_decrypt(iwp, f);
      }
      else
        udap::Warn("short packet of ", sz, " bytes");
    }

    static void
    handle_crypto_outbound(void *u);

    static void
    handle_frame_encrypt(iwp_async_frame *frame)
    {
      session *self = static_cast< session * >(frame->user);
      udap::Debug("tx ", frame->sz);
      if(udap_ev_udp_sendto(self->udp, self->addr, frame->buf, frame->sz)
         == -1)
        udap::Warn("sendto failed");
    }

    iwp_async_frame *
    alloc_frame(const void *buf, size_t sz)
    {
      // TODO don't hard code 1500
      if(sz > 1500)
        return nullptr;

      iwp_async_frame *frame = new iwp_async_frame;
      if(buf)
        memcpy(frame->buf, buf, sz);
      frame->iwp        = iwp;
      frame->sz         = sz;
      frame->user       = this;
      frame->sessionkey = sessionkey;
      return frame;
    }

    void
    encrypt_frame_async_send(const void *buf, size_t sz)
    {
      // 64 bytes frame overhead for nonce and hmac
      iwp_async_frame *frame = alloc_frame(nullptr, sz + 64);
      memcpy(frame->buf + 64, buf, sz);
      auto padding = rand() % MAX_PAD;
      if(padding)
        crypto->randbytes(frame->buf + 64 + sz, padding);
      frame->sz += padding;
      outboundFrames.Put(frame);
    }

    void
    EncryptOutboundFrames()
    {
      std::queue< iwp_async_frame * > outq;
      outboundFrames.Process(outq);
      while(outq.size())
      {
        auto &front = outq.front();
        if(iwp_encrypt_frame(front))
          handle_frame_encrypt(front);
        delete front;
        outq.pop();
      }
    }

    static void
    handle_verify_intro(iwp_async_intro *intro);

    static void
    handle_introack_generated(iwp_async_introack *i);

    void
    intro_ack()
    {
      uint16_t w1sz = rand() % MAX_PAD;
      introack.buf  = workbuf;
      introack.sz   = (32 * 3) + w1sz;
      // randomize padding
      if(w1sz)
        crypto->randbytes(introack.buf + (32 * 3), w1sz);

      // randomize nonce
      introack.nonce = introack.buf + 32;
      crypto->randbytes(introack.nonce, 32);
      // token
      introack.token = token;

      // keys
      introack.remote_pubkey = remote;
      introack.secretkey     = eph_seckey;

      // call
      introack.user = this;
      introack.hook = &handle_introack_generated;
      working       = true;
      iwp_call_async_gen_introack(iwp, &introack);
    }

    void
    on_intro(const void *buf, size_t sz)
    {
      if(sz >= sizeof(workbuf))
      {
        // too big?
        udap::Error("intro too big");
        delete this;
        return;
      }
      // copy so we own it
      memcpy(workbuf, buf, sz);
      intro.buf = workbuf;
      intro.sz  = sz;
      // give secret key
      intro.secretkey = eph_seckey;
      // and nonce
      intro.nonce = intro.buf + 32;
      intro.user  = this;
      // set call back hook
      intro.hook = &handle_verify_intro;
      // put remote pubkey into this buffer
      intro.remote_pubkey = remote;

      // call
      EnterState(eIntroRecv);
      working = true;
      iwp_call_async_verify_intro(iwp, &intro);
    }

    void
    on_intro_ack(const void *buf, size_t sz);

    static udap_link *
    get_parent(udap_link_session *s);

    static void
    handle_generated_intro(iwp_async_intro *i)
    {
      session *link = static_cast< session * >(i->user);
      link->working = false;
      if(i->buf)
      {
        udap::Debug("send intro");
        if(udap_ev_udp_sendto(link->udp, link->addr, i->buf, i->sz) == -1)
        {
          udap::Warn("send intro failed");
          return;
        }
        link->EnterState(eIntroSent);
      }
      else
      {
        udap::Warn("failed to generate intro");
      }
    }

    static void
    handle_establish_timeout(void *user, uint64_t orig, uint64_t left);

    void
    introduce(uint8_t *pub)
    {
      memcpy(remote, pub, 32);
      intro.buf   = workbuf;
      size_t w0sz = (rand() % MAX_PAD);
      intro.sz    = (32 * 3) + w0sz;
      // randomize w0
      if(w0sz)
      {
        crypto->randbytes(intro.buf + (32 * 3), w0sz);
      }

      intro.nonce     = intro.buf + 32;
      intro.secretkey = eph_seckey;
      // copy in pubkey
      intro.remote_pubkey = remote;
      // randomize nonce
      crypto->randbytes(intro.nonce, 32);
      // async generate intro packet
      intro.user = this;
      intro.hook = &handle_generated_intro;
      working    = true;
      iwp_call_async_gen_intro(iwp, &intro);
      // start introduce timer
      establish_job_id = udap_logic_call_later(
          logic, {5000, this, &handle_establish_timeout});
    }

    // handle session being over
    // called right before deallocation
    void
    done();

    void
    EnterState(State st)
    {
      frame.alive();
      state = st;
      if(state == eSessionStartSent || state == eIntroAckSent)
      {
        PumpCryptoOutbound();
        // StartInboundCodel();
      }
    }
  };  // namespace iwp

  struct server
  {
    typedef std::mutex mtx_t;
    typedef std::lock_guard< mtx_t > lock_t;

    udap_router *router;
    udap_logic *logic;
    udap_crypto *crypto;
    udap_ev_loop *netloop;
    udap_async_iwp *iwp;
    udap_threadpool *worker;
    udap_link *parent = nullptr;
    udap_udp_io udp;
    udap::Addr addr;
    char keyfile[255];
    uint32_t timeout_job_id;

    typedef std::unordered_map< udap::Addr, udap_link_session *,
                                udap::addrhash >
        LinkMap_t;

    LinkMap_t m_sessions;
    mtx_t m_sessions_Mutex;

    typedef std::unordered_map< udap::PubKey, udap::Addr, udap::PubKeyHash >
        SessionMap_t;

    SessionMap_t m_Connected;
    mtx_t m_Connected_Mutex;

    udap::SecretKey seckey;

    server(udap_router *r, udap_crypto *c, udap_logic *l,
           udap_threadpool *w)
    {
      router = r;
      crypto = c;
      logic  = l;
      worker = w;
      iwp    = udap_async_iwp_new(crypto, logic, w);
    }

    ~server()
    {
      udap_async_iwp_free(iwp);
    }

    // set that src address has identity pubkey
    void
    MapAddr(const udap::Addr &src, const udap::PubKey &identity)
    {
      lock_t lock(m_Connected_Mutex);
      m_Connected[identity] = src;
    }

    static bool
    HasSessionToRouter(udap_link *l, const byte_t *pubkey)
    {
      server *serv = static_cast< server * >(l->impl);
      udap::PubKey pk(pubkey);
      lock_t lock(serv->m_Connected_Mutex);
      return serv->m_Connected.find(pk) != serv->m_Connected.end();
    }

    void
    TickSessions()
    {
      auto now = udap_time_now_ms();
      {
        lock_t lock(m_sessions_Mutex);
        std::set< udap::Addr > remove;
        for(auto &itr : m_sessions)
        {
          session *s = static_cast< session * >(itr.second->impl);
          if(s && s->Tick(now))
            remove.insert(itr.first);
        }

        for(const auto &addr : remove)
          RemoveSessionByAddr(addr);
      }
    }

    static bool
    SendToSession(udap_link *l, const byte_t *pubkey, udap_buffer_t buf)
    {
      server *serv = static_cast< server * >(l->impl);
      {
        lock_t lock(serv->m_Connected_Mutex);
        auto itr = serv->m_Connected.find(pubkey);
        if(itr != serv->m_Connected.end())
        {
          lock_t innerlock(serv->m_sessions_Mutex);
          auto inner_itr = serv->m_sessions.find(itr->second);
          if(inner_itr != serv->m_sessions.end())
          {
            udap_link_session *link = inner_itr->second;
            return link->sendto(link, buf);
          }
        }
      }
      return false;
    }

    void
    UnmapAddr(const udap::Addr &src)
    {
      lock_t lock(m_Connected_Mutex);
      // std::unordered_map< udap::pubkey, udap::Addr, udap::pubkeyhash >
      auto itr = std::find_if(
          m_Connected.begin(), m_Connected.end(),
          [src](const std::pair< udap::PubKey, udap::Addr > &item) -> bool {
            return src == item.second;
          });
      if(itr == std::end(m_Connected))
        return;

      // tell router we are done with this session
      router->SessionClosed(itr->first);

      m_Connected.erase(itr);
    }

    session *
    create_session(const udap::Addr &src)
    {
      auto s  = new session(&udp, iwp, crypto, logic, seckey, src);
      s->serv = this;
      return s;
    }

    bool
    has_session_to(const udap::Addr &dst)
    {
      lock_t lock(m_sessions_Mutex);
      return m_sessions.find(dst) != m_sessions.end();
    }

    session *
    find_session(const udap::Addr &addr)
    {
      lock_t lock(m_sessions_Mutex);
      auto itr = m_sessions.find(addr);
      if(itr == m_sessions.end())
        return nullptr;
      else
        return static_cast< session * >(itr->second->impl);
    }

    void
    put_session(const udap::Addr &src, session *impl)
    {
      udap_link_session *s = new udap_link_session;
      s->impl               = impl;
      s->sendto             = &session::sendto;
      s->timeout            = &session::is_timedout;
      s->close              = &session::close;
      s->get_remote_router  = &session::get_remote_router;
      s->established        = &session::set_established;
      s->get_parent         = &session::get_parent;
      {
        lock_t lock(m_sessions_Mutex);
        m_sessions.emplace(src, s);
        impl->parent       = m_sessions[src];
        impl->frame.router = router;
        impl->frame.parent = impl->parent;
        impl->our_router   = &router->rc;
      }
    }

    void
    clear_sessions()
    {
      lock_t lock(m_sessions_Mutex);
      auto itr = m_sessions.begin();
      while(itr != m_sessions.end())
      {
        session *s = static_cast< session * >(itr->second->impl);
        delete s;
        delete itr->second;
        itr = m_sessions.erase(itr);
      }
    }

    void
    RemoveSessionByAddr(const udap::Addr &addr)
    {
      auto itr = m_sessions.find(addr);
      if(itr != m_sessions.end())
      {
        udap::Debug("removing session ", addr);
        UnmapAddr(addr);
        session *s = static_cast< session * >(itr->second->impl);
        s->done();
        delete itr->second;
        m_sessions.erase(itr);
        delete s;
      }
    }

    uint8_t *
    pubkey()
    {
      return udap::seckey_topublic(seckey);
    }

    bool
    ensure_privkey()
    {
      udap::Debug("ensure transport private key at ", keyfile);
      std::error_code ec;
      if(!fs::exists(keyfile, ec))
      {
        if(!keygen(keyfile))
          return false;
      }
      std::ifstream f(keyfile);
      if(f.is_open())
      {
        f.read((char *)seckey.data(), seckey.size());
        return true;
      }
      return false;
    }

    bool
    keygen(const char *fname)
    {
      crypto->encryption_keygen(seckey);
      udap::Info("new transport key generated");
      std::ofstream f(fname);
      if(f.is_open())
      {
        f.write((char *)seckey.data(), seckey.size());
        return true;
      }
      return false;
    }

    static void
    handle_cleanup_timer(void *l, uint64_t orig, uint64_t left)
    {
      if(left)
        return;
      server *link         = static_cast< server * >(l);
      link->timeout_job_id = 0;
      link->TickSessions();
      link->issue_cleanup_timer(orig);
    }

    // this is called in net threadpool
    static void
    handle_recvfrom(struct udap_udp_io *udp, const struct sockaddr *saddr,
                    const void *buf, ssize_t sz)
    {
      server *link = static_cast< server * >(udp->user);

      session *s = link->find_session(*saddr);
      if(s == nullptr)
      {
        // new inbound session
        s = link->create_session(*saddr);
      }
      s->recv(buf, sz);
    }

    void
    cancel_timer()
    {
      if(timeout_job_id)
      {
        udap_logic_cancel_call(logic, timeout_job_id);
      }
      timeout_job_id = 0;
    }

    void
    issue_cleanup_timer(uint64_t timeout)
    {
      timeout_job_id = udap_logic_call_later(
          logic, {timeout, this, &server::handle_cleanup_timer});
    }
  };

  bool
  frame_state::inbound_frame_complete(uint64_t id)
  {
    bool success = false;
    std::vector< byte_t > msg;
    auto rxmsg = rx[id];
    if(rxmsg->reassemble(msg))
    {
      udap::ShortHash digest;
      auto buf = udap::Buffer< decltype(msg) >(msg);
      router->crypto.shorthash(digest, buf);
      if(memcmp(digest, rxmsg->msginfo.hash(), 32))
      {
        udap::Warn("message hash missmatch ",
                    udap::AlignedBuffer< 32 >(digest),
                    " != ", udap::AlignedBuffer< 32 >(rxmsg->msginfo.hash()));
        return false;
      }
      session *impl = static_cast< session * >(parent->impl);
      success       = router->HandleRecvLinkMessage(parent, buf);
      if(success)
      {
        if(id == 0)
        {
          if(impl->CheckRCValid())
          {
            if(!impl->IsEstablished())
            {
              impl->send_LIM();
              impl->session_established();
            }
          }
          else
          {
            udap::PubKey k = impl->remote_router.pubkey;
            udap::Warn("spoofed LIM from ", k);
            impl->parent->close(impl->parent);
            success = false;
          }
        }
      }
      if(!success)
        udap::Warn("failed to handle inbound message ", id);
    }
    else
    {
      udap::Warn("failed to reassemble message ", id);
    }
    delete rxmsg;
    rx.erase(id);
    return success;
  }  // namespace iwp

  void
  session::handle_verify_intro(iwp_async_intro *intro)
  {
    session *self = static_cast< session * >(intro->user);
    self->working = false;
    if(!intro->buf)
    {
      udap::Error("intro verify failed from ", self->addr, " via ",
                   self->serv->addr);
      return;
    }
    self->intro_ack();
  }

  void
  session::session_established()
  {
    udap::RouterID remote = remote_router.pubkey;
    udap::Info("session to ", remote, " established");
    EnterState(eEstablished);
    serv->MapAddr(addr, remote_router.pubkey);
    udap_logic_cancel_call(logic, establish_job_id);
  }

  void
  session::done()
  {
    auto logic = serv->logic;
    if(establish_job_id)
    {
      udap_logic_remove_call(logic, establish_job_id);
      handle_establish_timeout(this, 0, 0);
    }
    if(pump_recv_timer_id)
    {
      udap_logic_remove_call(logic, pump_recv_timer_id);
    }
    if(pump_send_timer_id)
    {
      udap_logic_remove_call(logic, pump_send_timer_id);
    }
  }

  void
  session::on_intro_ack(const void *buf, size_t sz)
  {
    if(sz >= sizeof(workbuf))
    {
      // too big?
      udap::Error("introack too big");
      serv->RemoveSessionByAddr(addr);
      return;
    }
    // copy buffer so we own it
    memcpy(workbuf, buf, sz);
    // set intro ack parameters
    introack.buf           = workbuf;
    introack.sz            = sz;
    introack.nonce         = workbuf + 32;
    introack.remote_pubkey = remote;
    introack.token         = token;
    introack.secretkey     = eph_seckey;
    introack.user          = this;
    introack.hook          = &handle_verify_introack;
    // async verify
    working = true;
    iwp_call_async_verify_introack(iwp, &introack);
  }

  void
  session::send_keepalive(void *user)
  {
    session *self = static_cast< session * >(user);
    // if both sides agree on invalidation
    if(self->is_invalidated())
    {
      // don't send keepalive
      return;
    }
    // all zeros means keepalive
    byte_t tmp[8] = {0};
    // set flags for tx
    frame_header hdr(tmp);
    hdr.flags() = self->frame.txflags;
    // send frame after encrypting
    auto buf  = udap::StackBuffer< decltype(tmp) >(tmp);
    self->now = udap_time_now_ms();
    self->encrypt_frame_async_send(buf.base, buf.sz);
    self->pump();
    self->PumpCryptoOutbound();
  }

  bool
  frame_state::got_acks(frame_header hdr, size_t sz)
  {
    if(hdr.size() > sz)
    {
      udap::Error("invalid ACKS frame size ", hdr.size(), " > ", sz);
      return false;
    }
    sz = hdr.size();
    if(sz < 12)
    {
      udap::Error("invalid ACKS frame size ", sz, " < 12");
      return false;
    }

    auto ptr = hdr.data();
    uint64_t msgid;
    uint32_t bitmask;
    memcpy(&msgid, ptr, 8);
    memcpy(&bitmask, ptr + 8, 4);

    auto itr = tx.find(msgid);
    if(itr == tx.end())
    {
      udap::Debug("ACK for missing TX frame msgid=", msgid);
      return true;
    }

    transit_message *msg = itr->second;

    msg->ack(bitmask);

    if(msg->completed())
    {
      udap::Debug("message transmitted msgid=", msgid);
      tx.erase(msgid);
      delete msg;
    }
    else
    {
      udap::Debug("message ", msgid, " retransmit fragments");
      msg->retransmit_frags(sendqueue, txflags);
    }

    return true;
  }

  udap_link *
  session::get_parent(udap_link_session *s)
  {
    session *link = static_cast< session * >(s->impl);
    return link->serv->parent;
  }

  void
  session::handle_verify_introack(iwp_async_introack *introack)
  {
    session *link = static_cast< session * >(introack->user);
    link->working = false;
    if(introack->buf == nullptr)
    {
      // invalid signature
      udap::Error("introack verify failed from ", link->addr);
      // link->serv->RemoveSessionByAddr(link->addr);
      return;
    }
    link->EnterState(eIntroAckRecv);
    link->session_start();
  }

  bool
  session::Tick(udap_time_t now)
  {
    if(timedout(now, SESSION_TIMEOUT))
    {
      // we are timed out
      // when we are done doing stuff with all of our frames from the crypto
      // workers we are done
      udap::Debug(addr, " timed out with ", frames, " frames left");
      return !working;
    }
    if(is_invalidated())
    {
      // both sides agreeed to session invalidation
      // terminate our session when all of our frames from the crypto workers
      // are done
      udap::Debug(addr, " invaldiated session with ", frames, " frames left");
      return !working;
    }
    // send keepalive if we are established or a session is made
    if(state == eEstablished || state == eLIMSent)
      send_keepalive(this);

    // pump frame state
    if(state == eEstablished)
    {
      frame.retransmit();
      pump();
      PumpCryptoOutbound();
    }
    // TODO: determine if we are too idle
    return false;
  }

  void
  session::PumpCryptoOutbound()
  {
    udap_threadpool_queue_job(serv->worker, {this, &handle_crypto_outbound});
  }

  void
  session::handle_crypto_outbound(void *u)
  {
    session *self = static_cast< session * >(u);
    self->EncryptOutboundFrames();
  }

  void
  session::handle_verify_session_start(iwp_async_session_start *s)
  {
    session *self = static_cast< session * >(s->user);
    self->working = false;
    if(!s->buf)
    {
      // verify fail
      // TODO: remove session?
      udap::Warn("session start verify failed from ", self->addr);
      return;
    }
    self->send_LIM();
  }

  server *
  link_alloc(struct udap_router *router, const char *keyfile,
             struct udap_crypto *crypto, struct udap_logic *logic,
             struct udap_threadpool *worker)
  {
    server *link = new server(router, crypto, logic, worker);
    udap::Zero(link->keyfile, sizeof(link->keyfile));
    strncpy(link->keyfile, keyfile, sizeof(link->keyfile));
    return link;
  }

  const char *
  link_name()
  {
    return "IWP";
  }

  void
  link_get_addr(struct udap_link *l, struct udap_ai *addr)
  {
    server *link = static_cast< server * >(l->impl);
    addr->rank   = 1;
    strncpy(addr->dialect, link_name(), sizeof(addr->dialect));
    memcpy(addr->enc_key, link->pubkey(), 32);
    memcpy(addr->ip.s6_addr, link->addr.addr6(), 16);
    addr->port = link->addr.port();
  }

  const char *
  outboundLink_name()
  {
    return "OWP";
  }

  bool
  link_configure(struct udap_link *l, struct udap_ev_loop *netloop,
                 const char *ifname, int af, uint16_t port)
  {
    server *link = static_cast< server * >(l->impl);

    if(!link->ensure_privkey())
    {
      udap::Error("failed to ensure private key");
      return false;
    }

    udap::Debug("configure link ifname=", ifname, " af=", af, " port=", port);
    // bind
    sockaddr_in ip4addr;
    sockaddr_in6 ip6addr;
    sockaddr *addr = nullptr;
    switch(af)
    {
      case AF_INET:
        addr = (sockaddr *)&ip4addr;
        udap::Zero(addr, sizeof(ip4addr));
        break;
      case AF_INET6:
        addr = (sockaddr *)&ip6addr;
        udap::Zero(addr, sizeof(ip6addr));
        break;
        // TODO: AF_PACKET
      default:
        udap::Error(__FILE__, "unsupported address family", af);
        return false;
    }

    addr->sa_family = af;

    if(!udap::StrEq(ifname, "*"))
    {
      if(!udap_getifaddr(ifname, af, addr))
      {
        udap::Error("failed to get address of network interface ", ifname);
        return false;
      }
    }
    else
      l->name = outboundLink_name;

    switch(af)
    {
      case AF_INET:
        ip4addr.sin_port = htons(port);
        break;
      case AF_INET6:
        ip6addr.sin6_port = htons(port);
        break;
        // TODO: AF_PACKET
      default:
        return false;
    }

    link->addr         = *addr;
    link->netloop      = netloop;
    link->udp.recvfrom = &server::handle_recvfrom;
    link->udp.user     = link;
    link->udp.tick     = nullptr;
    udap::Debug("bind IWP link to ", link->addr);
    if(udap_ev_add_udp(link->netloop, &link->udp, link->addr) == -1)
    {
      udap::Error("failed to bind to ", link->addr);
      return false;
    }
    return true;
  }

  bool
  link_start(struct udap_link *l, struct udap_logic *logic)
  {
    server *link = static_cast< server * >(l->impl);
    // give link implementations
    link->parent         = l;
    link->timeout_job_id = 0;
    link->logic          = logic;
    // start cleanup timer
    link->issue_cleanup_timer(100);
    return true;
  }

  bool
  link_stop(struct udap_link *l)
  {
    server *link = static_cast< server * >(l->impl);
    link->cancel_timer();
    udap_ev_close_udp(&link->udp);
    link->clear_sessions();
    return true;
  }

  void
  link_iter_sessions(struct udap_link *l, struct udap_link_session_iter iter)
  {
    server *link = static_cast< server * >(l->impl);
    auto sz      = link->m_sessions.size();
    if(sz)
    {
      udap::Debug("we have ", sz, "sessions");
      iter.link = l;
      // TODO: race condition with cleanup timer
      for(auto &item : link->m_sessions)
        if(item.second->impl)
          if(!iter.visit(&iter, item.second))
            return;
    }
  }

  bool
  link_try_establish(struct udap_link *l, struct udap_link_establish_job *job)
  {
    server *link = static_cast< server * >(l->impl);
    {
      udap::Addr dst(job->ai);
      udap::Debug("establish session to ", dst);
      session *s = link->find_session(dst);
      if(s == nullptr)
      {
        s = link->create_session(dst);
        link->put_session(dst, s);
      }
      s->establish_job = job;
      s->frame.alive();  // mark it alive
      s->introduce(job->ai.enc_key);
    }
    return true;
  }

  void
  link_mark_session_active(struct udap_link *link,
                           struct udap_link_session *s)
  {
    static_cast< session * >(s->impl)->frame.alive();
  }

  void
  link_free(struct udap_link *l)
  {
    server *link = static_cast< server * >(l->impl);
    delete link;
  }

  void
  session::handle_establish_timeout(void *user, uint64_t orig, uint64_t left)
  {
    if(orig == 0)
      return;
    session *self          = static_cast< session * >(user);
    self->establish_job_id = 0;
    if(self->establish_job)
    {
      auto job            = self->establish_job;
      self->establish_job = nullptr;
      job->link           = self->serv->parent;
      if(self->IsEstablished())
      {
        job->session = self->parent;
      }
      else
      {
        // timer timeout
        job->session = nullptr;
      }
      job->result(job);
    }
  }

  void
  session::handle_introack_generated(iwp_async_introack *i)
  {
    session *link = static_cast< session * >(i->user);
    if(i->buf)
    {
      // track it with the server here
      if(link->serv->has_session_to(link->addr))
      {
        // duplicate session
        udap::Warn("duplicate session to ", link->addr);
        delete link;
        return;
      }
      link->frame.alive();
      link->serv->put_session(link->addr, link);
      udap::Debug("send introack to ", link->addr, " via ", link->serv->addr);
      if(udap_ev_udp_sendto(link->udp, link->addr, i->buf, i->sz) == -1)
      {
        udap::Warn("sendto failed");
        return;
      }
      link->EnterState(eIntroAckSent);
    }
    else
    {
      // failed to generate?
      udap::Warn("failed to generate introack");
      delete link;
    }
  }
}  // namespace iwp

extern "C" {
void
iwp_link_init(struct udap_link *link, struct udap_iwp_args args)
{
  link->impl = iwp::link_alloc(args.router, args.keyfile, args.crypto,
                               args.logic, args.cryptoworker);
  link->name = iwp::link_name;
  link->get_our_address     = iwp::link_get_addr;
  link->configure           = iwp::link_configure;
  link->start_link          = iwp::link_start;
  link->stop_link           = iwp::link_stop;
  link->iter_sessions       = iwp::link_iter_sessions;
  link->try_establish       = iwp::link_try_establish;
  link->has_session_to      = iwp::server::HasSessionToRouter;
  link->sendto              = iwp::server::SendToSession;
  link->mark_session_active = iwp::link_mark_session_active;
  link->free_impl           = iwp::link_free;
}
}
