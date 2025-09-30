#include "../libtg.h"
#include "tg.h"
#include "send_query.h"
#include "mtproto/mtproto.h"
#include "errors.h"
#include "tg_log.h"
#include <assert.h>
#include <stdbool.h>
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
