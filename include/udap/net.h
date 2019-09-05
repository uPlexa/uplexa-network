#ifndef UDAP_NET_H
#define UDAP_NET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

bool
udap_getifaddr(const char* ifname, int af, struct sockaddr* addr);

#ifdef __cplusplus
}
#endif
#endif
