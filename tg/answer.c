#include "answer.h"
#include "updates.h"
#include "mtproto/mtproto.h"
#include "tg.h"
#include "strerr.h"
#include "mtproto/ack.h"
#include "../libtg.h"
#include "../essential/ld.h"

TG_ANSWER tg_parse_answer(tg_t *tg, tl_t *tl, uint64_t msg_id,
		void *ptr, int (*callback)(void *ptr, const tl_t *tl))
{
	ON_LOG(tg, "%s: %s", __func__,
			tl?TL_NAME_FROM_ID(tl->_id):"NULL");

	TG_ANSWER answer = TG_ANSWER_READ_AGAIN;

	if (tl == NULL){
		return TG_ANSWER_READ_AGAIN;
	}

	switch (tl->_id) {
		case id_rpc_result:
			{
				// handle result
				tl_rpc_result_t *rpc_result = 
					(tl_rpc_result_t *)tl;
				tl_t *result = rpc_result->result_;
				ON_LOG(tg, "got msg result: (%s) for msg_id: "_LD_"",
					result?TL_NAME_FROM_ID(result->_id):"NULL", 
					rpc_result->req_msg_id_); 

				// async callback
				if (tg->callback)
					tg->callback(tg->userdata, result->_id, result);

				if (msg_id == rpc_result->req_msg_id_){
					// got result!
					answer = TG_ANSWER_OK;
					
					// add to ack
					tg_add_msgid(tg, msg_id);
					
					ON_LOG(tg, "OK! We have result: %s", 
						result?TL_NAME_FROM_ID(result->_id):"NULL");
				
					// handle gzip
					if (result->_id == id_gzip_packed){
						tl_t *unziped = tg_mtproto_guzip(tg, result);
						result = unziped;
					}
					if (callback)
						if (callback(ptr, result))
							break;

				} else {
					ON_ERR(tg, "rpc_result: (%s) for wrong msg_id: "_LD_"",
						result?TL_NAME_FROM_ID(result->_id):"NULL",
						rpc_result->req_msg_id_); 
					// drop!
					/*tg_add_todrop(tg, rpc_result->req_msg_id_);*/
				}
			}
			break;
		
		case id_msg_detailed_info:
		case id_msg_new_detailed_info:
			{
				uint64_t msg_id_;
				if (tl->_id == id_msg_detailed_info)
					msg_id_ = ((tl_msg_detailed_info_t *)tl)->answer_msg_id_;
				else
					msg_id_ = ((tl_msg_new_detailed_info_t *)tl)->answer_msg_id_;
				if (msg_id == msg_id_){
					ON_LOG(tg, "answer has been already sended!");
					answer = TG_ANSWER_OK;
					// add to ack
					tg_add_msgid(tg, msg_id);
					if (callback)
						if (callback(ptr, tl))
							break;
				} else {
					ON_ERR(tg, "%s: %s for wrong msgid: "_LD_"",
							__func__, TL_NAME_FROM_ID(tl->_id), msg_id_);
				}
			}
			break;

		case id_bad_server_salt:
			{
				// resend query
				answer = TG_ANSWER_RESEND_QUERY;
				break;
			}
		
		case id_rpc_error:
			{	
				// show error
				char *err = tg_strerr(tl);
				ON_ERR(tg, "%s: %s", __func__, err);
				free(err);
				break;
			}
		case id_bad_msg_notification:
			{
				// show error
				char *err = tg_strerr(tl);
				ON_ERR(tg, "%s: %s", __func__, err);
				free(err);

				// add time diff
				/* TODO:  <28-08-25, yourname> */
				//pthread_mutex_lock(&tg->seqnm);
				//tg->timediff = ntp_time_diff();
				//pthread_mutex_unlock(&tg->seqnm);

				tl_bad_msg_notification_t *bmsgn = 
						(tl_bad_msg_notification_t *)tl;

				if (msg_id == bmsgn->bad_msg_id_){
					answer = TG_ANSWER_OK;
					// add to ack
					tg_add_msgid(tg, msg_id);
					// do callback
					if (callback)
						if (callback(ptr, tl))
							break;
				}
			}
			break; // run on_done
		
		case id_updatesTooLong: case id_updateShort:
		case id_updateShortMessage: case id_updateShortChatMessage:
		case id_updateShortSentMessage: case id_updatesCombined:
		case id_updates:
			// do updates
			ON_LOG(tg, "%s: got updates", __func__);
			//tg_do_updates(tg, tl);
			break;

		case id_msg_container:
			{
				tl_msg_container_t *container = 
					(tl_msg_container_t *)tl; 
				ON_LOG(tg, "%s: container %d long", 
						__func__, container->messages_len);
				int i;
				for (i = 0; i < container->messages_len; ++i) {
					mtp_message_t m = container->messages_[i];
					// parse answer for each message
					tl_t *tl = tl_deserialize(&m.body);
					TG_ANSWER new = tg_parse_answer(tg, tl, msg_id, ptr, callback);
					if (answer != TG_ANSWER_OK)
						answer = new;
					// free tl
					tl_free(tl);
				}
			}
			break;

		case id_gzip_packed:
			{
				// handle gzip
				tl_t *tl = tg_mtproto_guzip(tg, tl);
				tg_parse_answer(tg, tl, msg_id, ptr, callback);
				// free tl
				tl_free(tl);
			}
			break;

		case id_new_session_created:
			{
				// handle new session
				ON_LOG(tg, "new session created...");
			}
			break;
		
		case id_msgs_ack:
			{
				tl_msgs_ack_t *ack = (tl_msgs_ack_t *)tl;
				// check msg_id
				int i;
				for (i = 0; i < ack->msg_ids_len; ++i) {
					if (msg_id == ack->msg_ids_[i]){
						answer = TG_ANSWER_OK;
						ON_LOG(tg, "ACK for result!");
						if (callback)
							if (callback(ptr, tl))
								break;
					}
				}
			}
			break;

		case id_resPQ:
		case id_server_DH_params_ok: 
		case id_server_DH_params_fail:
			{
				// callback RFC messages
				ON_LOG(tg, "RFC message!");
				if (callback)
					(callback(ptr, tl));
				return TG_ANSWER_OK;
			}

		default:
			{
				ON_LOG(tg, "%s: don't know how to handle: %s", __func__,
						TL_NAME_FROM_ID(tl->_id));
				break;
			}
	}

	return TG_ANSWER_READ_AGAIN;
}
