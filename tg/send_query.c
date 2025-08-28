#include "send_query.h"
#include "../libtg.h"
#include "tg.h"
#include "answer.h"
#include "mtproto/mtproto.h"
#include "transport/http.h"
#include <stdint.h>

#ifndef TG_TEST
#define TG_TEST 0
#endif /* ifndef TG_TEST */

void tg_send_query(
		tg_t *tg, buf_t *query, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl))
{
	tg_send_query_with_progress(
			tg, query, tg->dc.id, 
			ptr, callback,
			NULL, NULL);
}

void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, int dc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress)
{
	uint64_t msgid;
	buf_t mtproto = tg_mtproto_transport(
			tg, query, true, &msgid);
	
	if (mtproto.size){
		buf_t answer = tg_http_transport(
				tg, dc, 80, false,
			 	TG_TEST, *query, 
				progressp, progress);

		buf_t payload = tg_mtproto_detransport(
				tg, &answer, true);
		buf_free(answer);
	
		tl_t *tl	= tl_deserialize(&payload);

		tg_parse_answer(tg, tl, msgid, 
				ptr, callback);
	}
}
