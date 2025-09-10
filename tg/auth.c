#include "../config.h"
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

tl_user_t *
tg_is_authorized(tg_t *tg)
{
	if (tg->key.size){
		ON_LOG(tg, "have auth_key with len: %d", tg->key.size);

		// init connection and get config
		buf_t getConfig = tl_help_getConfig();
		buf_t init = initConnection(tg, getConfig);
		buf_free(getConfig);
		
		tl_t *tl = 
			tg_send_query_sync(tg, &init, true); 
		buf_free(init);

		if (tl == NULL || tl->_id !=id_config){
			ON_ERR(tg, "can't get config!");
			return NULL;
		}

		tg->config = (tl_config_t *)tl;
		tl = NULL;

		// check if authorized
		InputUser iuser = tl_inputUserSelf();
		//ON_LOG_BUF(tg, iuser, "%s: InputUser: ", __func__);
		
		buf_t getUsers = 
			tl_users_getUsers(&iuser, 1);	
		//ON_LOG_BUF(tg, getUsers, "%s: getUsers: ", __func__);
		buf_free(iuser);

		tl = tg_send_query_sync(tg, &getUsers, true); 
		buf_free(getUsers);

		if (tl == NULL){
			ON_ERR(tg, "TL is NULL");
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

	ON_ERR(tg, "NEED_TO_AUTHORIZE");
	return NULL;
}

tl_auth_sentCode_t *
tg_auth_sendCode(tg_t *tg, const char *phone_number) 
{
	tl_t *tl = NULL;
	ON_LOG(tg, "%s", __func__);
	
	// init connection and get config
	buf_t getConfig = tl_help_getConfig();
	buf_t init = initConnection(tg, getConfig);
	buf_free(getConfig);

	tl = tg_send_query_sync(tg, &init, true); 
	buf_free(init);

	if (tl == NULL || tl->_id !=id_config){
		ON_ERR(tg, "can't get config!");
		return NULL;
	}

	ON_LOG(tg, "got config!");
	tg->config = (tl_config_t *)tl;

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

	tl = tg_send_query_sync(tg, &sendCode, true); 
	buf_free(sendCode);

	if (tl == NULL){
		ON_ERR(tg, "TL is NULL");
		return NULL;
	}

	if (tl->_id == id_rpc_error){
		tl_rpc_error_t *error = (tl_rpc_error_t *)tl;
		char *str = 
			strstr((char *)error->error_message_.data, "PHONE_MIGRATE_");
		if (str){
			// reconnect to another DC
			str += strlen("PHONE_MIGRATE_");
			int dc = atoi(str);
			tg->dc = DCs[dc-1]; 
			
			// generate new auth key
			tg_socket_close(tg, tg->socket);
			tg_new_auth_key_mtx(tg);
			tg->key.size = 0;
			return tg_auth_sendCode(tg, phone_number);
		}
	}
	
	if (!tl){
		ON_ERR(tg, "TL is NULL");
		return NULL;
	}
		
	if (tl->_id == id_auth_sentCode){
		return (tl_auth_sentCode_t *)tl;
	}

	tl_free(tl);
	return NULL;
}

tl_auth_authorization_t *
tg_auth_signIn(tg_t *tg, tl_auth_sentCode_t *sentCode, 
		const char *phone_number, const char *phone_code) 
{
	ON_LOG(tg, "%s", __func__);
	buf_t signIn = 
		tl_auth_signIn(
				phone_number, 
				(char *)sentCode->phone_code_hash_.data, 
				phone_code, 
				NULL);
	
	tl_t *tl = 
		tg_send_query_sync(tg, &signIn, true);
	buf_free(signIn);

	if (!tl){
		ON_ERR(tg, "TL is NULL");
		return NULL;
	}
	
	if (tl->_id == id_rpc_error){
		tl_rpc_error_t *error = (tl_rpc_error_t *)tl;
		// throw error
		ON_ERR(tg, "%s", error->error_message_.data);
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

	if (tl)
		tl_free(tl);

	return NULL;
}
