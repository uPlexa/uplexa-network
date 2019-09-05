#ifndef UDAP_HPP
#define UDAP_HPP

#include <udap.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace udap
{
  struct Context
  {
    Context(std::ostream &stdout, bool signleThread = false);
    ~Context();

    int num_nethreads   = 1;
    bool singleThreaded = false;
    std::vector< std::thread > netio_threads;
    udap_crypto crypto;
    udap_router *router                  = nullptr;
    udap_threadpool *worker              = nullptr;
    udap_logic *logic                    = nullptr;
    udap_config *config                  = nullptr;
    udap_nodedb *nodedb                  = nullptr;
    udap_ev_loop *mainloop               = nullptr;
    udap_dht_msg_handler custom_dht_func = nullptr;
    char nodedb_dir[256]                  = {0};

    bool
    LoadConfig(const std::string &fname);

    void
    Close();

    int
    LoadDatabase();

    int
    IterateDatabase(struct udap_nodedb_iter i);

    bool
    PutDatabase(struct udap_rc *rc);

    struct udap_rc *
    GetDatabase(const byte_t *pk);

    int
    Run();

    void
    HandleSignal(int sig);

   private:
    void
    SigINT();

    bool
    ReloadConfig();

    static void
    iter_config(udap_config_iterator *itr, const char *section,
                const char *key, const char *val);

    void
    progress();

    std::string configfile;

    std::ostream &out;
  };
}

#endif
