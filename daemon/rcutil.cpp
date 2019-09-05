#include <udap.h>
#include <signal.h>
#include "logger.hpp"

struct udap_main *ctx = 0;

udap_main *sudap = nullptr;

void
handle_signal(int sig)
{
  if(ctx)
    udap_main_signal(ctx, sig);
}

#ifndef TESTNET
#define TESTNET 0
#endif

#include <getopt.h>
#include <udap/router_contact.h>
#include <udap/time.h>
#include <fstream>
#include "buffer.hpp"
#include "crypto.hpp"
#include "fs.hpp"
#include "router.hpp"

bool
printNode(struct udap_nodedb_iter *iter)
{
  char ftmp[68] = {0};
  const char *hexname =
      udap::HexEncode< udap::PubKey, decltype(ftmp) >(iter->rc->pubkey, ftmp);

  printf("[%zu]=>[%s]\n", iter->index, hexname);
  return false;
}

int
main(int argc, char *argv[])
{
  // take -c to set location of daemon.ini
  // --generate-blank /path/to/file.signed
  // --update-ifs /path/to/file.signed
  // --key /path/to/long_term_identity.key
  // --import
  // --export

  // --generate /path/to/file.signed
  // --update /path/to/file.signed
  // printf("has [%d]options\n", argc);
  if(argc < 2)
  {
    printf(
        "please specify: \n"
        "--generate with a path to a router contact file\n"
        "--update   with a path to a router contact file\n"
        "--list     \n"
        "--import   with a path to a router contact file\n"
        "--export   with a path to a router contact file\n"
        "\n");
    return 0;
  }
  bool genMode    = false;
  bool updMode    = false;
  bool listMode   = false;
  bool importMode = false;
  bool exportMode = false;
  int c;
  char *conffname;
  char defaultConfName[] = "daemon.ini";
  conffname              = defaultConfName;
  char *rcfname;
  char defaultRcName[]     = "other.signed";
  rcfname                  = defaultRcName;
  bool haveRequiredOptions = false;
  while(1)
  {
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"generate", required_argument, 0, 'g'},
        {"update", required_argument, 0, 'u'},
        {"list", no_argument, 0, 'l'},
        {"import", required_argument, 0, 'i'},
        {"export", required_argument, 0, 'e'},
        {0, 0, 0, 0}};
    int option_index = 0;
    c = getopt_long(argc, argv, "cgluie", long_options, &option_index);
    if(c == -1)
      break;
    switch(c)
    {
      case 0:
        break;
      case 'c':
        conffname = optarg;
        break;
      case 'l':
        haveRequiredOptions = true;
        listMode            = true;
        break;
      case 'i':
        // printf ("option -g with value `%s'\n", optarg);
        rcfname             = optarg;
        haveRequiredOptions = true;
        importMode          = true;
        break;
      case 'e':
        // printf ("option -g with value `%s'\n", optarg);
        rcfname             = optarg;
        haveRequiredOptions = true;
        exportMode          = true;
        break;
      case 'g':
        // printf ("option -g with value `%s'\n", optarg);
        rcfname             = optarg;
        haveRequiredOptions = true;
        genMode             = true;
        break;
      case 'u':
        // printf ("option -u with value `%s'\n", optarg);
        rcfname             = optarg;
        haveRequiredOptions = true;
        updMode             = true;
        break;
      default:
        abort();
    }
  }
  if(!haveRequiredOptions)
  {
    udap::Error("Parameters dont all have their required parameters.\n");
    return 0;
  }
  printf("parsed options\n");
  if(!genMode && !updMode && !listMode && !importMode && !exportMode)
  {
    udap::Error("I don't know what to do, no generate or update parameter\n");
    return 0;
  }

  ctx = udap_main_init(conffname, !TESTNET);
  if(!ctx)
  {
    udap::Error("Cant set up context");
    return 0;
  }
  signal(SIGINT, handle_signal);

  udap_rc tmp;
  if(genMode)
  {
    printf("Creating [%s]\n", rcfname);
    // Jeff wanted tmp to be stack created
    // do we still need to zero it out?
    udap_rc_clear(&tmp);
    // if we zero it out then
    // allocate fresh pointers that the bencoder can expect to be ready
    tmp.addrs = udap_ai_list_new();
    tmp.exits = udap_xi_list_new();
    // set updated timestamp
    tmp.last_updated = udap_time_now_ms();
    // load longterm identity
    udap_crypto crypt;
    udap_crypto_libsodium_init(&crypt);

    // which is in daemon.ini config: router.encryption-privkey (defaults
    // "encryption.key")
    fs::path encryption_keyfile = "encryption.key";
    udap::SecretKey encryption;
    udap_findOrCreateEncryption(&crypt, encryption_keyfile.c_str(),
                                 &encryption);
    udap_rc_set_pubenckey(&tmp, udap::seckey_topublic(encryption));

    // get identity public sig key
    fs::path ident_keyfile = "identity.key";
    byte_t identity[SECKEYSIZE];
    udap_findOrCreateIdentity(&crypt, ident_keyfile.c_str(), identity);
    udap_rc_set_pubsigkey(&tmp, udap::seckey_topublic(identity));

    // this causes a segfault
    udap_rc_sign(&crypt, identity, &tmp);
    // set filename
    fs::path our_rc_file = rcfname;
    // write file
    udap_rc_write(&tmp, our_rc_file.c_str());
    // release memory for tmp lists
    udap_rc_free(&tmp);
  }
  if(updMode)
  {
    printf("rcutil.cpp - Loading [%s]\n", rcfname);
    udap_rc *rc = udap_rc_read(rcfname);

    // set updated timestamp
    rc->last_updated = udap_time_now_ms();
    // load longterm identity
    udap_crypto crypt;
    udap_crypto_libsodium_init(&crypt);
    fs::path ident_keyfile = "identity.key";
    byte_t identity[SECKEYSIZE];
    udap_findOrCreateIdentity(&crypt, ident_keyfile.c_str(), identity);
    // get identity public key
    uint8_t *pubkey = udap::seckey_topublic(identity);
    udap_rc_set_pubsigkey(rc, pubkey);
    udap_rc_sign(&crypt, identity, rc);

    // set filename
    fs::path our_rc_file_out = "update_debug.rc";
    // write file
    udap_rc_write(&tmp, our_rc_file_out.c_str());
  }
  if(listMode)
  {
    udap_main_loadDatabase(ctx);
    udap_nodedb_iter iter;
    iter.visit = printNode;
    udap_main_iterateDatabase(ctx, iter);
  }
  if(importMode)
  {
    udap_main_loadDatabase(ctx);
    udap::Info("Loading ", rcfname);
    udap_rc *rc = udap_rc_read(rcfname);
    if(!rc)
    {
      udap::Error("Can't load RC");
      return 0;
    }
    udap_main_putDatabase(ctx, rc);
  }
  if(exportMode)
  {
    udap_main_loadDatabase(ctx);
    // udap::Info("Looking for string: ", rcfname);

    udap::PubKey binaryPK;
    udap::HexDecode(rcfname, binaryPK.data());

    udap::Info("Looking for binary: ", binaryPK);
    struct udap_rc *rc = udap_main_getDatabase(ctx, binaryPK.data());
    if(!rc)
    {
      udap::Error("Can't load RC from database");
    }
    std::string filename(rcfname);
    filename.append(".signed");
    udap::Info("Writing out: ", filename);
    udap_rc_write(rc, filename.c_str());
  }
  udap_main_free(ctx);
  return 1;  // success
}
