#include "peer.h"
#include <assert.h>

tg_peer_t tg_peer_get_with_id(
		tg_t *tg, 
		tl_t **users, int users_len, 
		tl_t **chats, int chats_len, 
		uint64_t id)
{
	ON_LOG(tg, "%s", __func__);
	assert(users);
	assert(chats);
	tg_peer_t peer;
	memset(&peer, 0, sizeof(tg_peer_t));

	int i;
	
	// iterate users
	for (i = 0; i < users_len; ++i) {
		if (users[i] && users[i]->_id == id_user){
			tl_user_t *user = (tl_user_t *)users[i];
			if (user->id_ == id){
				peer.type = TG_PEER_USER;
				peer.tl = (tl_t *)user;
				peer.title = (const char *)user->username_.data;
				return peer;
			}
		}
	}

	// iterate chats
	for (i = 0; i < chats_len; ++i) {
		if (chats[i] && chats[i]->_id == id_chat)
		{
			tl_chat_t *chat = (tl_chat_t *)chats[i];
			if (chat->id_ == id){
				peer.type = TG_PEER_CHAT;
				peer.tl = (tl_t *)chat;
				peer.title = (const char *)chat->title_.data;
				return peer;
			}
		}
		if (chats[i] && chats[i]->_id == id_channel)
		{
			tl_channel_t *channel = (tl_channel_t *)chats[i];
			if (channel->id_ == id){
				peer.type = TG_PEER_CHANNEL;
				peer.tl = (tl_t *)channel;
				peer.title = (const char *)channel->title_.data;
				return peer;
			}
		}
	}

	return peer;
}
