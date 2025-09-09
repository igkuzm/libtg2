/**
 * File              : socket.h
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 09.09.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#ifndef TG_NET_H
#define TG_NET_H

#include <stdint.h>
#include "../../libtg.h"
#include "progress.h"

typedef int socket_t;

extern socket_t tg_socket_open (tg_t*, const char *ip, int port);
extern void     tg_socket_close(tg_t*, socket_t);
extern int      tg_socket_send_query(
															 tg_t *tg, int socket, buf_t *query);
extern int      tg_socket_send_query_with_progress(
		                           tg_t *tg, int socket, buf_t *query,
		                           void *progressp, tg_progress_fun *);
extern buf_t    tg_socket_receive_query(
															 tg_t *tg, int socket);
extern buf_t    tg_socket_receive_query_with_progress(
		                           tg_t *tg, int socket,
		                           void *progressp, tg_progress_fun *);
#endif /* defined(TG_NET_H) */
