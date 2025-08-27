/**
 * File              : net.h
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 28.08.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#ifndef TG_NET_H
#define TG_NET_H

#include <stdint.h>
#include "../../libtg.h"

typedef int socket_t;

extern socket_t tg_net_open_socket(tg_t*, const char *ip, int port);
extern void     tg_net_close_socket(tg_t*, socket_t);

#endif /* defined(TG_NET_H) */
