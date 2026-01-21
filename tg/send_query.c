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


tl_t *tg_send_query_sync(tg_t *tg, buf_t *query);

void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, enum dc dc, bool enc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress);

void tg_send_query(tg_t *tg, buf_t *query) 
{
	tg_send_query_with_progress(
			tg, query, tg->dc.dc, true, 
			NULL, NULL,
			NULL, NULL);
}

static tl_t *tg_send_query_read(tg_t *tg, bool enc)
{
	buf_t answer = tg_socket_receive_query(tg, tg->socket);
	buf_t payload = tg_mtproto_unpack(tg, &answer, enc);
	/*buf_free(answer);*/
	tl_t *tl = tl_deserialize(&payload);
	/*buf_free(payload);*/
	return tl;
}

void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, enum dc dc, bool enc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress)
{
	uint64_t msgid;
	buf_t pack = tg_mtproto_pack(tg, query, enc, &msgid);
	
	if (pack.size){

		int socket = tg_socket_open(tg, tg->dc.ipv4, tg->port);
		if (socket < 0 ||
				tg_socket_send_query(tg, tg->socket, &pack) < 0)
		{
			return;
		}

		// read
		tl_t *tl = tg_send_query_read(tg, enc);

		TG_ANSWER ret = 
			tg_parse_answer(tg, tl, msgid, ptr, callback);
		if (ret == TG_ANSWER_RESEND_QUERY){
			ON_LOG(tg, "%s: bad server salt - resend query", __func__);
			tl_free(tl);
			tg_socket_close(tg, socket);
			tg_send_query_with_progress(tg, query, dc, enc, 
					ptr, callback, progressp, progress);
		}

		while (ret == TG_ANSWER_READ_AGAIN) {
			ON_LOG(tg, "%s: read again", __func__);
			tl_free(tl);
			tl = tg_send_query_read(tg, enc);
			ret = tg_parse_answer(tg, tl, msgid, ptr, callback);
		}

		tl_free(tl);
		tg_socket_close(tg, socket);
	}
}

int tg_send_query_sync_cb(void *d, const tl_t *answer){
	tl_t **tl = (tl_t **)d;	
	buf_t buf = answer->_buf;
	*tl = tl_deserialize(&buf);
	return 0;
}


static tl_t * tg_send_query_sync_parse_answer(
		tg_t *tg, buf_t answer, bool enc, uint64_t msgid)
{
	tl_t *tl = NULL;
	buf_t payload = tg_mtproto_unpack(tg, &answer, enc);

	tl_t *deserialized = tl_deserialize(&payload);
	buf_free(payload);

	if (tg_parse_answer(tg, deserialized, msgid, 
			&tl, tg_send_query_sync_cb) == TG_ANSWER_RESEND_QUERY)
	{
		return deserialized;
	}

	tl_free(deserialized);
	return tl;
}

static tl_t * tg_send_query_sync_receive(
		tg_t *tg, bool enc, uint64_t msgid)
{
	tl_t *tl = NULL;
		
	buf_t answer = tg_socket_receive_query(tg, tg->socket);
	tl = tg_send_query_sync_parse_answer(tg, answer, enc, msgid);

	buf_free(answer);
	return tl;
}

static tl_t *tg_send_query_sync_enc_dc_with_progress(
		tg_t *tg, buf_t *query, 
		bool enc, enum dc dc,
		void *progressp, tg_progress_fun *progress)
{
	tl_t *tl = NULL;
	uint64_t msgid;
	buf_t pack = tg_mtproto_pack(tg, query, enc,  &msgid);

	ON_LOG_BUF(tg, pack, "%s: Data to send: ", __func__);
	
	if (pack.size == 0)
		return NULL;

	if (tg_socket_send_query(tg, tg->socket, &pack) < 0){
		return NULL;
	}

	tl = tg_send_query_sync_receive(tg, enc, msgid);

	// handle ACK - get data again
	if (tl && tl->_id == id_msgs_ack){
		tl_free(tl);
		tl = tg_send_query_sync_receive(tg, enc, msgid);
	}

	// handle bad server salt 
	if (tl && tl->_id == id_bad_server_salt){
		// resend query
		tl_free(tl);
		return tg_send_query_sync(tg, query);
	}

	// log errors
	if (tl && tl->_id == id_rpc_error){
		ON_LOG(tg, "%s: %s", __func__, 
				STRING_T_TO_STR(((tl_rpc_error_t *)tl)->error_message_));
	}

	return tl;
}	
		
tl_t *tg_send_query_sync(tg_t *tg, buf_t *query)
{
	tl_t *tl = tg_send_query_sync_enc_dc_with_progress(
			tg, query, true, tg->dc.dc, 
			NULL, NULL);
	return tl;
}	

tl_t *tg_send_rfc(tg_t *tg, buf_t *query)
{
	tl_t *tl = tg_send_query_sync_enc_dc_with_progress(
			tg, query, false, tg->dc.dc,
			NULL, NULL);
	return tl;
}	

tl_t *tg_file_transfer(
		tg_t *tg, buf_t *query, enum dc dc, 
		void *progressp, tg_progress_fun *progress)
{
	tl_t *tl = tg_send_query_sync_enc_dc_with_progress(
			tg, query, false, tg->dc.dc,
			progressp, progress);
	return tl;
}


void tg_send_query_async(tg_t *tg, buf_t *query, 
	void *userdata, 
	int callback(void *userdata, const tl_t *tl))
{
	return tg_send_query_with_progress(
			tg, query, tg->dc.dc, true, 
			userdata, callback, 
			NULL, NULL);
}	
