#include <udap.h>
#include <signal.h>

struct udap_main *ctx = 0;

void
handle_signal(int sig)
{
  if(ctx)
    udap_main_signal(ctx, sig);
}

#ifndef TESTNET
#define TESTNET 0
#endif

int
main(int argc, char *argv[])
{
  const char *conffname = "daemon.ini";
  if(argc > 1)
    conffname = argv[1];
  ctx      = udap_main_init(conffname, !TESTNET);
  int code = 1;
  if(ctx)
  {
    signal(SIGINT, handle_signal);
    code = udap_main_run(ctx);
    udap_main_free(ctx);
  }
  return code;
}
