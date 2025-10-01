#ifndef TG_PEER_H
#define TG_PEER_H
#include "tg.h"
#include "../libtg.h"

extern tg_peer_t tg_peer_get_with_id(
		tg_t *tg, 
		tl_t **users, int users_len, 
		tl_t **chats, int chats_len, 
		uint64_t id);

#endif /* ifndef TG_PEER_H */
