#include "auth.h"
#include "../config.h"
#include "errors.h"
#include "tg.h"
#include "../libtg.h"
#include <stdio.h>
#include <stdlib.h>
#include "../essential/strtok_foreach.h"
#include "../essential/serialize.h"
#include "send_query.h"
#include "tg_log.h"
#include "transport/socket.h"
#include "auth_key_mtx.h"

buf_t initConnection(tg_t *tg, buf_t query)
{
	buf_t initConnection = 
		tl_initConnection(
				tg->apiId,
				PACKAGE_NAME, 
				PACKAGE_VERSION, 
				PACKAGE_VERSION, 
				"ru", 
				"LibTg", 
				"ru", 
				NULL, 
				NULL, 
				&query);
	
	/*ON_LOG_BUF(tg, initConnection, */
			/*"%s: initConnection: ", __func__);*/
	
	buf_t invokeWithLayer = 
		tl_invokeWithLayer(
				API_LAYER, &initConnection);
	
	/*ON_LOG_BUF(tg, invokeWithLayer, */
			/*"%s: invokeWithLayer: ", __func__);*/
	
	return invokeWithLayer;
}

tl_config_t *
tg_init_and_get_config(tg_t *tg)
{
	// init connection and get config
	buf_t getConfig = tl_help_getConfig();
	buf_t init = initConnection(tg, getConfig);
	buf_free(getConfig);
	
	tl_t *tl = tg_send_query_sync(tg, &init); 
	buf_free(init);

	if (tl == NULL || tl->_id !=id_config){
		ON_ERR(tg, "can't get config!");
		return NULL;
	}

	return (tl_config_t *)tl;
}

tl_user_t *
tg_is_authorized(tg_t *tg)
{
	if (tg->key.size){
		ON_LOG(tg, "have auth_key with len: %d", tg->key.size);

		// open socket
		tg->socket = tg_socket_open(tg, tg->dc.ipv4, tg->port);

		tg->config = tg_init_and_get_config(tg);
		if (!tg->config)
			goto end;

		// check if authorized
		InputUser iuser = tl_inputUserSelf();
		//ON_LOG_BUF(tg, iuser, "%s: InputUser: ", __func__);
		
		buf_t getUsers = 
			tl_users_getUsers(&iuser, 1);	
		//ON_LOG_BUF(tg, getUsers, "%s: getUsers: ", __func__);
		buf_free(iuser);

		tl_t *tl = tg_send_query_sync(tg, &getUsers); 
		buf_free(getUsers);

		if (tl == NULL){
			ON_ERR(tg, "TL is NULL");
			goto end;
		}
	
		if (tl->_id == id_rpc_error){
			ON_ERR(tg, "%s: %s", __func__, RPC_ERROR(tl));
			tl_free(tl);
			return NULL;
		}
		
		if (tl->_id == id_vector){
			tl_vector_t *vector = (tl_vector_t *)tl;
			ON_LOG(tg, "got vector with len: %d", vector->len_);
			//ON_LOG_BUF(tg, vector->data_, "VECTOR DATA: ");
			tl_t *user = tl_deserialize(&vector->data_);
			if (user && user->_id == id_user){
				return (tl_user_t *)user;
			}
		}

		return NULL;
	}

end:
	tg_socket_close(tg, tg->socket);
	ON_ERR(tg, "NEED_TO_AUTHORIZE");
	return NULL;
}

tl_auth_sentCode_t *
tg_auth_sendCode(tg_t *tg, const char *phone_number) 
{
	tl_t *tl = NULL;
	ON_LOG(tg, "%s", __func__);
	
	// init connection and get config
	tg->config = tg_init_and_get_config(tg);
	if (!tg->config)
		return NULL;

	CodeSettings codeSettings = tl_codeSettings(
			false,
			 false,
			 false,
			 false,
			 false, 
			false,
			 NULL,
			 0,
			 NULL,
			 NULL);

		ON_LOG_BUF(tg, codeSettings, 
			"%s: codeSettings: ", __func__);

	buf_t sendCode = 
		tl_auth_sendCode(
				phone_number, 
				tg->apiId, 
				tg->apiHash, 
				&codeSettings);
	ON_LOG_BUF(tg, sendCode, 
			"%s: sendCode: ", __func__);
	buf_free(codeSettings);

	tl = tg_send_query_sync(tg, &sendCode); 
	buf_free(sendCode);

	if (tl == NULL){
		ON_ERR(tg, "%s: TL is NULL", __func__);
		return NULL;
	}

	if (tl->_id == id_rpc_error){
		// ckeck FLOOD_WAIT
		int wait = tg_error_flood_wait(tg, RPC_ERROR(tl));
		if (wait){
			ON_ERR(tg, 
					"You are blocked for flooding. Wait %.2d:%.2d:%2d",
					wait/3600, wait%3600/60, wait%3600%60);
			
			tl_free(tl);
			return NULL;
		}

		// check PHONE_MIGRATE
		const dc_t *dc = 
			tg_error_phone_migrate(tg, RPC_ERROR(tl));
		if (dc){
			tg->dc = *dc; 
			// generate new auth key and reconnect
			tg_socket_close(tg, tg->socket);
			tg_new_auth_key_mtx(tg);
			tg->key.size = 0;
			tl_free(tl);
			return tg_auth_sendCode(tg, phone_number);
		}

		// throw other errors
		ON_ERR(tg, "%s: %s", __func__, RPC_ERROR(tl));
		tl_free(tl);
		return NULL;
	}
	
		if (tl->_id == id_auth_sentCode){
		return (tl_auth_sentCode_t *)tl;
	}

	ON_ERR(tg, "%s: expected id_auth_sentCode but got: %s",
			__func__, TL_NAME_FROM_ID(tl->_id));
	tl_free(tl);
	return NULL;
}

tl_auth_authorization_t *
tg_auth_signIn(tg_t *tg, tl_auth_sentCode_t *sentCode, 
		const char *phone_number, const char *phone_code,
		AUTH_ERR_CODE *err_code) 
{
	ON_LOG(tg, "%s", __func__);

	tl_t *tl = NULL;

	buf_t signIn = 
		tl_auth_signIn(
				phone_number, 
				(char *)sentCode->phone_code_hash_.data, 
				phone_code, 
				NULL);
	
	tl = tg_send_query_sync(tg, &signIn);
	buf_free(signIn);

	if (!tl){
		ON_ERR(tg, "TL is NULL");
		return NULL;
	}

	if (tl->_id == id_rpc_error){
		// check auth err codes
		AUTH_ERR_CODE code = 
			tg_error_auth_err_code(tg, RPC_ERROR(tl));
		if (code != AUTH_ERR_CODE_OK)
		{
			if (err_code)
				*err_code = code;
			tl_free(tl);
			return NULL;
		}

		// throw other errors
		ON_ERR(tg, "%s: %s", __func__, RPC_ERROR(tl));
		tl_free(tl);
		return NULL;
	}
	
	if (tl->_id == id_auth_authorization){
		tl_auth_authorization_t *auth =
			(tl_auth_authorization_t *)tl;

		if (auth->setup_password_required_){
			// throw error
			ON_ERR(tg, "SESSION_PASSWORD_NEEDED");
			return NULL;
		}
		
		return auth;
	}

	ON_ERR(tg, "%s: expected id_auth_authorization but got: %s",
			__func__, TL_NAME_FROM_ID(tl->_id));
	tl_free(tl);
	return NULL;
}
