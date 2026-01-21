#include "../tg.h"
#include "header.h"
#include "stb_ds.h"
#include <pthread.h>
#include "../../essential/ld.h"

void tg_add_msgid(tg_t *tg, uint64_t msgid){
	ON_LOG(tg, "%s", __func__);
	tg_do_in_msgids_locked(tg)
	{
		arrput(tg->msgids, msgid);
	}
}

buf_t tg_ack(tg_t *tg)
{
	ON_LOG(tg, "%s", __func__);
	buf_t ack = buf_new();
	
	// send ACK
	tg_do_in_msgids_locked(tg)
	{
		int i, len = arrlen(tg->msgids);
		if (len < 1){
			// no messages to acknolage
			pthread_mutex_unlock(&tg->lock_msgids);
			return ack;
		}

		//for (i = 0; i < len; ++i) {
			//ON_ERR(tg, "ACK: "_LD_"", tg->msgids[i]);
		//}

		ack = tl_msgs_ack(
				tg->msgids, len);

		// free msgids
		arrfree(tg->msgids);
		tg->msgids = NULL;
	}

	return ack;
}

void tg_add_todrop(tg_t *tg, uint64_t msgid){
	ON_LOG(tg, "%s", __func__);
	tg_do_in_todrop_locked(tg)
	{
		arrput(tg->todrop, msgid);
	}
}

int tg_to_drop(tg_t *tg, buf_t *buf)
{
	int i = 0, len;
	ON_LOG(tg, "%s", __func__);
	
	// send ACK
	tg_do_in_todrop_locked(tg)
	{
		len = arrlen(tg->todrop);
		if (len < 1){
			pthread_mutex_unlock(&tg->lock_todrop);
			return 0;
		}
	
		for (i = 0; i < len; ++i) {
			buf_t drop = tl_rpc_drop_answer(tg->todrop[i]);
			buf_t msg = tg_mtp_message(
					tg, &drop, NULL, true);
			buf_free(drop);
			*buf = buf_cat_buf(*buf, msg);
			buf_free(msg);
		}

		// free msgids
		arrfree(tg->todrop);
		tg->todrop = NULL;
	}
	
	return i;
}
