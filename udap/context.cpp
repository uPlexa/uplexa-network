#include <udap.h>
#include <signal.h>
#include <udap.hpp>
#include "logger.hpp"
#include "router.hpp"

#if(__FreeBSD__)
#include <pthread_np.h>
#endif

namespace udap
{
  Context::Context(std::ostream &stdout, bool singleThread)
      : singleThreaded(singleThread), out(stdout)
  {
    udap::Info(UDAP_VERSION, " ", UDAP_RELEASE_MOTTO);
  }

  Context::~Context()
  {
  }

  void
  Context::progress()
  {
    out << "." << std::flush;
  }

  bool
  Context::ReloadConfig()
  {
    // udap::Info("loading config at ", configfile);
    if(udap_load_config(config, configfile.c_str()))
    {
      udap_free_config(&config);
      udap::Error("failed to load config file ", configfile);
      return false;
    }
    udap_config_iterator iter;
    iter.user  = this;
    iter.visit = &iter_config;
    udap_config_iter(config, &iter);
    udap::Info("config [", configfile, "] loaded");
    return true;
  }

  void
  Context::iter_config(udap_config_iterator *itr, const char *section,
                       const char *key, const char *val)
  {
    Context *ctx = static_cast< Context * >(itr->user);
    if(!strcmp(section, "router"))
    {
      if(!strcmp(key, "worker-threads") && !ctx->singleThreaded)
      {
        int workers = atoi(val);
        if(workers > 0 && ctx->worker == nullptr)
        {
          ctx->worker = udap_init_threadpool(workers, "udap-worker");
        }
      }
      if(!strcmp(key, "net-threads"))
      {
        ctx->num_nethreads = atoi(val);
        if(ctx->num_nethreads <= 0)
          ctx->num_nethreads = 1;
        if(ctx->singleThreaded)
          ctx->num_nethreads = 0;
      }
    }
    if(!strcmp(section, "netdb"))
    {
      if(!strcmp(key, "dir"))
      {
        strncpy(ctx->nodedb_dir, val, sizeof(ctx->nodedb_dir));
      }
    }
  }

  int
  Context::LoadDatabase()
  {
    udap_crypto_libsodium_init(&crypto);
    nodedb = udap_nodedb_new(&crypto);
    if(!nodedb_dir[0])
    {
      udap::Error("no nodedb_dir configured");
      return 0;
    }

    nodedb_dir[sizeof(nodedb_dir) - 1] = 0;
    if(!udap_nodedb_ensure_dir(nodedb_dir))
    {
      udap::Error("nodedb_dir is incorrect");
      return 0;
    }
    // udap::Info("nodedb_dir [", nodedb_dir, "] configured!");
    ssize_t loaded = udap_nodedb_load_dir(nodedb, nodedb_dir);
    udap::Info("nodedb_dir loaded ", loaded, " RCs from [", nodedb_dir, "]");
    if(loaded < 0)
    {
      // shouldn't be possible
      udap::Error("nodedb_dir directory doesn't exist");
      return 0;
    }
    return 1;
  }

  int
  Context::IterateDatabase(struct udap_nodedb_iter i)
  {
    return udap_nodedb_iterate_all(nodedb, i);
  }

  bool
  Context::PutDatabase(struct udap_rc *rc)
  {
    return udap_nodedb_put_rc(nodedb, rc);
  }

  struct udap_rc *
  Context::GetDatabase(const byte_t *pk)
  {
    return udap_nodedb_get_rc(nodedb, pk);
  }

  int
  Context::Run()
  {
    udap::Info("starting up");
    this->LoadDatabase();
    udap_ev_loop_alloc(&mainloop);

    // ensure worker thread pool
    if(!worker && !singleThreaded)
      worker = udap_init_threadpool(2, "udap-worker");
    else if(singleThreaded)
    {
      udap::Info("running in single threaded mode");
      worker = udap_init_same_process_threadpool();
    }
    // ensure netio thread
    if(singleThreaded)
    {
      logic = udap_init_single_process_logic(worker);
    }
    else
      logic = udap_init_logic();

    router = udap_init_router(worker, mainloop, logic);

    if(udap_configure_router(router, config))
    {
      if(custom_dht_func)
      {
        udap::Info("using custom dht function");
        udap_dht_set_msg_handler(router->dht, custom_dht_func);
      }
      udap_run_router(router, nodedb);
      // run net io thread
      if(singleThreaded)
      {
        udap::Info("running mainloop");
        udap_ev_loop_run_single_process(mainloop, worker, logic);
      }
      else
      {
        auto netio = mainloop;
        while(num_nethreads--)
        {
          netio_threads.emplace_back([netio]() { udap_ev_loop_run(netio); });
#if(__APPLE__ && __MACH__)

#elif(__FreeBSD__)
          pthread_set_name_np(netio_threads.back().native_handle(),
                              "udap-netio");
#else
          pthread_setname_np(netio_threads.back().native_handle(),
                             "udap-netio");
#endif
        }
        udap::Info("running mainloop");
        udap_logic_mainloop(logic);
      }
      return 0;
    }
    else
      udap::Error("Failed to configure router");
    return 1;
  }

  void
  Context::HandleSignal(int sig)
  {
    if(sig == SIGINT)
    {
      udap::Info("SIGINT");
      SigINT();
    }
    if(sig == SIGHUP)
    {
      udap::Info("SIGHUP");
      ReloadConfig();
    }
  }

  void
  Context::SigINT()
  {
    Close();
  }

  void
  Context::Close()
  {
    udap::Debug("stop router");
    if(router)
      udap_stop_router(router);

    udap::Debug("stop workers");
    if(worker)
      udap_threadpool_stop(worker);

    udap::Debug("join workers");
    if(worker)
      udap_threadpool_join(worker);

    udap::Debug("stop logic");

    if(logic)
      udap_logic_stop(logic);

    udap::Debug("free config");
    udap_free_config(&config);

    udap::Debug("free workers");
    udap_free_threadpool(&worker);

    udap::Debug("free nodedb");
    udap_nodedb_free(&nodedb);

    for(size_t i = 0; i < netio_threads.size(); ++i)
    {
      if(mainloop)
      {
        udap::Debug("stopping event loop thread ", i);
        udap_ev_loop_stop(mainloop);
      }
    }

    udap::Debug("free router");
    udap_free_router(&router);

    udap::Debug("free logic");
    udap_free_logic(&logic);

    for(auto &t : netio_threads)
    {
      udap::Debug("join netio thread");
      t.join();
    }

    netio_threads.clear();
    udap::Debug("free mainloop");
    udap_ev_loop_free(&mainloop);
  }

  bool
  Context::LoadConfig(const std::string &fname)
  {
    udap_new_config(&config);
    configfile = fname;
    return ReloadConfig();
  }
}

extern "C" {
struct udap_main
{
  std::unique_ptr< udap::Context > ctx;
};

struct udap_main *
udap_main_init(const char *fname, bool multiProcess)
{
  if(!fname)
    fname = "daemon.ini";

  udap_main *m = new udap_main;
  m->ctx.reset(new udap::Context(std::cout, !multiProcess));
  if(!m->ctx->LoadConfig(fname))
  {
    m->ctx->Close();
    delete m;
    return nullptr;
  }
  return m;
}

void
udap_main_set_dht_handler(struct udap_main *ptr, udap_dht_msg_handler func)
{
  ptr->ctx->custom_dht_func = func;
}

void
udap_main_signal(struct udap_main *ptr, int sig)
{
  ptr->ctx->HandleSignal(sig);
}

int
udap_main_run(struct udap_main *ptr)
{
  return ptr->ctx->Run();
}

int
udap_main_loadDatabase(struct udap_main *ptr)
{
  return ptr->ctx->LoadDatabase();
}

int
udap_main_iterateDatabase(struct udap_main *ptr, struct udap_nodedb_iter i)
{
  return ptr->ctx->IterateDatabase(i);
}

bool
udap_main_putDatabase(struct udap_main *ptr, struct udap_rc *rc)
{
  return ptr->ctx->PutDatabase(rc);
}

struct udap_rc *
udap_main_getDatabase(struct udap_main *ptr, byte_t *pk)
{
  return ptr->ctx->GetDatabase(pk);
}

void
udap_main_free(struct udap_main *ptr)
{
  delete ptr;
}
}
