#include "../libtg.h"
#include "tg.h"
#include "send_query.h"
#include "mtproto/mtproto.h"
#include "errors.h"
#include "tg_log.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "peer.h"
#ifdef _WIN32
#include <windows.h> 
#else
#include <unistd.h>
#endif

struct tg_get_dialogs_t {
	tg_t *tg; 
	void *data; 
	int (*callback)(void *, const tl_messages_dialogs_t *);
	int count;
	int total;
	uint64_t *hash; 
	uint32_t offset_id; 
	uint32_t offset_date; 
};

static int tg_get_dialogs_callback(void *data, const tl_t *tl)
{
	assert(data && tl);
	struct tg_get_dialogs_t *t = (struct tg_get_dialogs_t *)data;
	
	ON_LOG(t->tg, "%s", __func__);

	// handle FLOOD WAIT
	if (tl->_id == id_rpc_error){
		// ckeck FLOOD_WAIT
		int wait = tg_error_flood_wait(t->tg, RPC_ERROR(tl));
		if (wait){
			ON_LOG(t->tg, "%s: waiting for %d seconds", __func__, wait);
#ifdef _WIN32
			Sleep(wait * 1000);
#else
			sleep(wait);
#endif
		}
	}
	
	tl_messages_dialogs_t *md;
	bool should_free_md = false; 

	if (tl->_id != id_messages_dialogsSlice &&
			tl->_id != id_messages_dialogs)
	{
		ON_ERR(t->tg, "%s: no dialogs loaded", __func__);
		return 1;
	}

	if (tl->_id == id_messages_dialogsSlice)
	{
		md = NEW(tl_messages_dialogs_t, return 1;);
		should_free_md = true;

		tl_messages_dialogsSlice_t *mds = 
			(tl_messages_dialogsSlice_t *)tl;

		// set total count of dialogs
		t->total = mds->count_;
		
		md->dialogs_ = mds->dialogs_; 
		md->dialogs_len = mds->dialogs_len; 
		md->chats_ = mds->chats_;
		md->chats_len = mds->chats_len;
		md->messages_ = mds->messages_;
		md->messages_len = mds->messages_len;
		md->users_ = mds->users_;
		md->users_len = mds->users_len;
	}

	if (tl->_id == id_messages_dialogs)
	{
		md = (tl_messages_dialogs_t *)tl;
	}

	t->count += md->dialogs_len;
	ON_LOG(t->tg, "%s: got %d dialogs of: %d", __func__, 
			t->count, t->total);

	// get offset_id
	tl_dialog_t *last_dialog = 
		(tl_dialog_t *)md->dialogs_[md->dialogs_len-1];
	if (last_dialog && last_dialog->_id == id_dialog){
		t->offset_id = last_dialog->top_message_;
	}
	else
		ON_ERR(t->tg, "%s: can't get last message", __func__);

	if (t->callback)
		t->callback(t->data, md);

	if (should_free_md)
		free(md);

	return 0;
}

void tg_get_dialogs(
		tg_t *tg, 
		int limit, 
		uint32_t offset_date, 
		uint64_t *hash, 
		uint32_t *folder_id, 
		void *data, 
		int (*callback)(void *, const tl_messages_dialogs_t *))
{
	ON_LOG(tg, "%s", __func__);
	struct tg_get_dialogs_t t =
	{tg, data, callback,
  	0, 1, hash, -1,
	offset_date};

	InputPeer inputPeer = tl_inputPeerSelf();

	for (t.count = 0; t.count < t.total; ) {
		buf_t getDialogs = 
			tl_messages_getDialogs(
					NULL,
				folder_id, 
				t.offset_date,
				t.offset_id, 
				&inputPeer, 
				limit>0?limit:20,
				hash?*t.hash:0);

		tg_send_query(tg, &getDialogs, 
				&t, tg_get_dialogs_callback);
		
		buf_free(getDialogs);
		if (limit > 0)
			break;
	}

	buf_free(inputPeer);
}

tg_message_t tg_dialogs_get_dialog_top_message(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, int idx)
{
	ON_LOG(tg, "%s", __func__);
	assert(dialogs);
	tg_message_t msg;
	memset(&msg, 0, sizeof(tg_message_t));

	if (idx < 0 || idx >= dialogs->dialogs_len){
		ON_ERR(tg, "%s: idx is out of dialogs len", __func__);
		return msg;
	}
	
	tl_dialog_t *dialog = (tl_dialog_t *)dialogs->dialogs_[idx];
	if (!dialog || dialog->_id != id_dialog){
		ON_ERR(tg, "%s: no dialog at index: %d", __func__, idx);
		return msg;
	}

	// iterate messages
	int i;
	for (i = 0; i < dialogs->messages_len; ++i) {
		tl_message_t *message = 
			(tl_message_t *)dialogs->messages_[i];	
		if (message && message->_id == id_message){
			if (message->id_ == dialog->top_message_)
			{	
				ON_LOG(tg, "%s: %d", __func__, __LINE__);
				if (message->from_id_){
					msg.from = tg_peer_get_with_id(tg, 
							dialogs->users_, dialogs->users_len, 
							dialogs->chats_, dialogs->chats_len, 
							((tl_peerChat_t *)message->from_id_)->chat_id_);
				}
				msg.msg = message;
				return msg;
			}
		}
	}

	return msg;
}

tg_peer_t tg_dialogs_get_peer_with_peer_id(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, uint64_t id)
{
	ON_LOG(tg, "%s", __func__);
	assert(dialogs);

	return tg_peer_get_with_id(tg, 
			dialogs->users_, dialogs->users_len, 
			dialogs->chats_, dialogs->chats_len, 
			id);
}

tg_peer_t tg_dialogs_get_peer(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, int idx)
{	
	ON_LOG(tg, "%s", __func__);
	assert(dialogs);
	tg_peer_t peer;
	memset(&peer, 0, sizeof(tg_peer_t));

	if (idx < 0 || idx >= dialogs->dialogs_len){
		ON_ERR(tg, "%s: idx is out of dialogs len", __func__);
		return peer;
	}
	
	tl_dialog_t *dialog = (tl_dialog_t *)dialogs->dialogs_[idx];
	if (!dialog || dialog->_id != id_dialog){
		ON_ERR(tg, "%s: no dialog at index: %d", __func__, idx);
		return peer;
	}
 
	uint64_t id = ((tl_peerChat_t *)dialog->peer_)->chat_id_;
	
	return tg_dialogs_get_peer_with_peer_id(tg, dialogs, id);
}
