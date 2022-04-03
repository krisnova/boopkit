//
// Created by nova on 4/2/22.
//

#include <netinet/in.h>

#ifndef ENOHONK_HONK_H
#define ENOHONK_HONK_H

struct tcp_honk {
  __u8 saddr[sizeof(struct sockaddr_in6)];
};


#endif // ENOHONK_HONK_H
