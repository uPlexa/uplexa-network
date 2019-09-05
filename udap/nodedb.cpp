#include <udap/crypto_async.h>
#include <udap/nodedb.h>
#include <udap/router_contact.h>

#include <fstream>
#include <udap/crypto.hpp>
#include <unordered_map>
#include "buffer.hpp"
#include "encode.hpp"
#include "fs.hpp"
#include "logger.hpp"
#include "mem.hpp"

static const char skiplist_subdirs[] = "0123456789abcdef";

struct udap_nodedb
{
  udap_nodedb(udap_crypto *c) : crypto(c)
  {
  }

  udap_crypto *crypto;
  // std::map< udap::pubkey, udap_rc  > entries;
  std::unordered_map< udap::PubKey, udap_rc, udap::PubKeyHash > entries;
  fs::path nodePath;

  void
  Clear()
  {
    auto itr = entries.begin();
    while(itr != entries.end())
    {
      udap_rc_clear(&itr->second);
      itr = entries.erase(itr);
    }
  }

  udap_rc *
  getRC(const udap::PubKey &pk)
  {
    return &entries[pk];
  }

  bool
  Has(const udap::PubKey &pk)
  {
    return entries.find(pk) != entries.end();
  }

  /*
    bool
    Has(const byte_t *pk)
    {
      udap::PubKey test(pk);
      auto itr = this->entries.begin();
      while(itr != this->entries.end())
      {
        udap::Info("Has byte_t [", test.size(), "] vs [", itr->first.size(),
    "]"); if (memcmp(test.data(), itr->first.data(), 32) == 0) {
          udap::Info("Match");
        }
        itr++;
      }
      return entries.find(pk) != entries.end();
    }
  */

  bool
  pubKeyExists(udap_rc *rc)
  {
    // extract pk from rc
    udap::PubKey pk = rc->pubkey;
    // return true if we found before end
    return entries.find(pk) != entries.end();
  }

  bool
  check(udap_rc *rc)
  {
    if(!pubKeyExists(rc))
    {
      // we don't have it
      return false;
    }
    udap::PubKey pk = rc->pubkey;

    // TODO: zero out any fields you don't want to compare

    // serialize both and memcmp
    byte_t nodetmp[MAX_RC_SIZE];
    auto nodebuf = udap::StackBuffer< decltype(nodetmp) >(nodetmp);
    if(udap_rc_bencode(&entries[pk], &nodebuf))
    {
      byte_t paramtmp[MAX_RC_SIZE];
      auto parambuf = udap::StackBuffer< decltype(paramtmp) >(paramtmp);
      if(udap_rc_bencode(rc, &parambuf))
      {
        if(nodebuf.sz == parambuf.sz)
          return memcmp(&parambuf, &nodebuf, parambuf.sz) == 0;
      }
    }
    return false;
  }

  std::string
  getRCFilePath(const byte_t *pubkey)
  {
    char ftmp[68] = {0};
    const char *hexname =
        udap::HexEncode< udap::PubKey, decltype(ftmp) >(pubkey, ftmp);
    std::string hexString(hexname);
    std::string filepath = nodePath;
    filepath.append(PATH_SEP);
    filepath.append(&hexString[hexString.length() - 1]);
    filepath.append(PATH_SEP);
    filepath.append(hexname);
    filepath.append(".signed");
    return filepath;
  }

  bool
  setRC(udap_rc *rc)
  {
    byte_t tmp[MAX_RC_SIZE];
    auto buf = udap::StackBuffer< decltype(tmp) >(tmp);

    // extract pk from rc
    udap::PubKey pk = rc->pubkey;

    // set local db entry to have a copy we own
    udap_rc entry;
    udap::Zero(&entry, sizeof(entry));
    udap_rc_copy(&entry, rc);
    entries[pk] = entry;

    if(udap_rc_bencode(&entry, &buf))
    {
      buf.sz        = buf.cur - buf.base;
      auto filepath = getRCFilePath(pk);
      udap::Debug("saving RC.pubkey ", filepath);
      std::ofstream ofs(
          filepath,
          std::ofstream::out & std::ofstream::binary & std::ofstream::trunc);
      ofs.write((char *)buf.base, buf.sz);
      ofs.close();
      if(!ofs)
      {
        udap::Error("Failed to write: ", filepath);
        return false;
      }
      udap::Debug("saved RC.pubkey: ", filepath);
      return true;
    }
    return false;
  }

  ssize_t
  Load(const fs::path &path)
  {
    std::error_code ec;
    if(!fs::exists(path, ec))
    {
      return -1;
    }
    ssize_t loaded = 0;

    for(const char &ch : skiplist_subdirs)
    {
      std::string p;
      p += ch;
      fs::path sub = path / p;

      ssize_t l = loadSubdir(sub);
      if(l > 0)
        loaded += l;
    }
    return loaded;
  }

  ssize_t
  loadSubdir(const fs::path &dir)
  {
    ssize_t sz = 0;
    fs::directory_iterator i(dir);
    auto itr = i.begin();
    while(itr != itr.end())
    {
      if(fs::is_regular_file(itr->symlink_status()) && loadfile(*itr))
        sz++;

      ++itr;
    }
    return sz;
  }

  bool
  loadfile(const fs::path &fpath)
  {
#if __APPLE__ && __MACH__
    // skip .DS_Store files
    if(strstr(fpath.c_str(), ".DS_Store") != 0)
    {
      return false;
    }
#endif
    udap_rc *rc = udap_rc_read(fpath.c_str());
    if(!rc)
    {
      udap::Error("Signature read failed", fpath);
      return false;
    }
    if(!udap_rc_verify_sig(crypto, rc))
    {
      udap::Error("Signature verify failed", fpath);
      return false;
    }
    udap::PubKey pk(rc->pubkey);
    entries[pk] = *rc;
    return true;
  }

  bool
  iterate(struct udap_nodedb_iter i)
  {
    i.index  = 0;
    auto itr = entries.begin();
    while(itr != entries.end())
    {
      i.rc = &itr->second;
      i.visit(&i);

      // advance
      i.index++;
      itr++;
    }
    return true;
  }

  /*
  bool Save()
  {
    auto itr = entries.begin();
    while(itr != entries.end())
    {
      udap::pubkey pk = itr->first;
      udap_rc *rc= itr->second;

      itr++; // advance
    }
    return true;
  }
  */
};

// call request hook
void
logic_threadworker_callback(void *user)
{
  udap_async_verify_rc *verify_request =
      static_cast< udap_async_verify_rc * >(user);
  verify_request->hook(verify_request);
}

// write it to disk
void
disk_threadworker_setRC(void *user)
{
  udap_async_verify_rc *verify_request =
      static_cast< udap_async_verify_rc * >(user);
  verify_request->valid = verify_request->nodedb->setRC(&verify_request->rc);
  udap_logic_queue_job(verify_request->logic,
                        {verify_request, &logic_threadworker_callback});
}

// we run the crypto verify in the crypto threadpool worker
void
crypto_threadworker_verifyrc(void *user)
{
  udap_async_verify_rc *verify_request =
      static_cast< udap_async_verify_rc * >(user);
  verify_request->valid =
      udap_rc_verify_sig(verify_request->nodedb->crypto, &verify_request->rc);
  // if it's valid we need to set it
  if(verify_request->valid)
  {
    udap::Debug("RC is valid, saving to disk");
    udap_threadpool_queue_job(verify_request->diskworker,
                               {verify_request, &disk_threadworker_setRC});
  }
  else
  {
    // callback to logic thread
    udap::Warn("RC is not valid, can't save to disk");
    udap_logic_queue_job(verify_request->logic,
                          {verify_request, &logic_threadworker_callback});
  }
}

void
nodedb_inform_load_rc(void *user)
{
  udap_async_load_rc *job = static_cast< udap_async_load_rc * >(user);
  job->hook(job);
}

void
nodedb_async_load_rc(void *user)
{
  udap_async_load_rc *job = static_cast< udap_async_load_rc * >(user);

  auto fpath  = job->nodedb->getRCFilePath(job->pubkey);
  job->loaded = job->nodedb->loadfile(fpath);
  if(job->loaded)
  {
    udap_rc_clear(&job->rc);
    udap_rc_copy(&job->rc, job->nodedb->getRC(job->pubkey));
  }
  udap_logic_queue_job(job->logic, {job, &nodedb_inform_load_rc});
}

extern "C" {
struct udap_nodedb *
udap_nodedb_new(struct udap_crypto *crypto)
{
  return new udap_nodedb(crypto);
}

void
udap_nodedb_free(struct udap_nodedb **n)
{
  if(*n)
  {
    auto i = *n;
    *n     = nullptr;
    i->Clear();
    delete i;
  }
}

bool
udap_nodedb_ensure_dir(const char *dir)
{
  fs::path path(dir);
  std::error_code ec;
  if(!fs::exists(dir, ec))
    fs::create_directories(path, ec);

  if(ec)
    return false;

  if(!fs::is_directory(path))
    return false;

  for(const char &ch : skiplist_subdirs)
  {
    std::string p;
    p += ch;
    fs::path sub = path / p;
    fs::create_directory(sub, ec);
    if(ec)
      return false;
  }
  return true;
}

ssize_t
udap_nodedb_load_dir(struct udap_nodedb *n, const char *dir)
{
  std::error_code ec;
  if(!fs::exists(dir, ec))
  {
    return -1;
  }
  n->nodePath = dir;
  return n->Load(dir);
}

bool
udap_nodedb_put_rc(struct udap_nodedb *n, struct udap_rc *rc)
{
  return n->setRC(rc);
}

int
udap_nodedb_iterate_all(struct udap_nodedb *n, struct udap_nodedb_iter i)
{
  n->iterate(i);
  return n->entries.size();
}

void
udap_nodedb_async_verify(struct udap_async_verify_rc *job)
{
  // switch to crypto threadpool and continue with
  // crypto_threadworker_verifyrc
  udap_threadpool_queue_job(job->cryptoworker,
                             {job, &crypto_threadworker_verifyrc});
}

void
udap_nodedb_async_load_rc(struct udap_async_load_rc *job)
{
  // call in the disk io thread so we don't bog down the others
  udap_threadpool_queue_job(job->diskworker, {job, &nodedb_async_load_rc});
}

struct udap_rc *
udap_nodedb_get_rc(struct udap_nodedb *n, const byte_t *pk)
{
  // udap::Info("udap_nodedb_get_rc [", pk, "]");
  if(n->Has(pk))
    return n->getRC(pk);
  else
    return nullptr;
}

size_t
udap_nodedb_num_loaded(struct udap_nodedb *n)
{
  return n->entries.size();
}

void
udap_nodedb_select_random_hop(struct udap_nodedb *n, struct udap_rc *prev,
                               struct udap_rc *result, size_t N)
{
  /// TODO: check for "guard" status for N = 0?
  auto sz = n->entries.size();

  if(prev)
  {
    do
    {
      auto itr = n->entries.begin();
      if(sz > 1)
      {
        auto idx = rand() % sz;
        std::advance(itr, idx);
      }
      if(memcmp(prev->pubkey, itr->second.pubkey, PUBKEYSIZE) == 0)
        continue;
      udap_rc_copy(result, &itr->second);
      return;
    } while(true);
  }
  else
  {
    auto itr = n->entries.begin();
    if(sz > 1)
    {
      auto idx = rand() % sz;
      std::advance(itr, idx);
    }
    udap_rc_copy(result, &itr->second);
  }
}

}  // end extern
