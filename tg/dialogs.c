#include "../libtg.h"
#include "tg.h"
#include "send_query.h"
#include "mtproto/mtproto.h"
#include <assert.h>
#include <stdbool.h>

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
		ON_LOG(t->tg, "%s: dialogsSlice len: %d", __func__, mds->count_);
		
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

	// get offset_id
	tl_message_t *last_message = 
		(tl_message_t *)md->messages_[md->messages_len-1];
	if (last_message && last_message->_id == id_message){
		t->offset_id = last_message->_id;
		t->offset_date = last_message->date_;
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
	int i;
	
	struct tg_get_dialogs_t t =
	{tg, data, callback,
  	0, 1, hash, -1,
	offset_date};

	InputPeer inputPeer = tl_inputPeerSelf();

	for (i = 0; i < t.total; i+=t.count) {
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
