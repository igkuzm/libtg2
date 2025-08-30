#include "send_query.h"
#include "../libtg.h"
#include "tg.h"
#include "answer.h"
#include "mtproto/mtproto.h"
#include "tg_log.h"
#include "transport/http.h"
#include "transport/socket.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef TG_TEST
#define TG_TEST 1
#endif /* ifndef TG_TEST */

void tg_send_query(
		tg_t *tg, buf_t *query, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl))
{
	tg_send_query_with_progress(
			tg, query, tg->dc.dc, true, 
			ptr, callback,
			NULL, NULL);
}

void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, enum dc dc, bool enc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress)
{
	uint64_t msgid;
	buf_t pack = tg_mtproto_pack(tg, query, enc, &msgid);
	
	if (pack.size){
		buf_t answer = tg_http_send_query(
				tg, dc, 443, false,
			 	TG_TEST, &pack, 
				progressp, progress);

		ON_LOG(tg, "%s: answer: %s", __func__, answer.data);

		buf_t payload = tg_mtproto_unpack(tg, &answer, enc);
		buf_free(answer);
	
		tl_t *tl	= tl_deserialize(&payload);

		tg_parse_answer(tg, tl, msgid, 
				ptr, callback);

		tl_free(tl);
	}
}
		
tl_t *tg_send_query_sync(
		tg_t *tg, buf_t *query, bool enc)
{
	tl_t *tl = NULL;
	uint64_t msgid;
	buf_t pack = tg_mtproto_pack(tg, query, enc,  &msgid);

	ON_LOG_BUF(tg, pack, "%s: Data to send: ", __func__);
	
	if (pack.size){
		buf_t answer = 
			tg_socket_send_query(tg, tg->socket, &pack);

		buf_t payload = tg_mtproto_unpack(tg, &answer, enc);
		buf_free(answer);
	
		tl	= tl_deserialize(&payload);
	};

	return tl;
}	
