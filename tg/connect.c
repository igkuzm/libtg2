#include "auth_key_mtx.h"
/*#include "auth_key1.h"*/
#include "errors.h"
#include "send_query.h"
#include "tg.h"
#include "../essential/strtok_foreach.h"
#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "tg_log.h"
#include "transport/socket.h"

#define _TG_CB(tg, type, data)\
	({\
	 void *ret = NULL;\
	 if (tg->callback){\
		ret = tg->callback(tg->userdata, type, (void *)data);\
	 }\
	 ret;\
	})

int tg_connect(tg_t *tg)
{
	// check connection
	int socket = tg_socket_open(tg, tg->dc.ipv4, tg->port);
	if (socket < 0){
		// no connection
		ON_ERR(tg, "%s: no connection", __func__);
		return 1;
	}
	tg_socket_close(tg, socket);

	// check if authorized
	tl_user_t *user = tg_is_authorized(tg);
	if (user){
		_TG_CB(tg, TG_AUTH_AUTHORIZED_AS_USER, user);
		return 1;
	}

	// get new auth key
	if (tg_new_auth_key_mtx(tg)){
		ON_ERR(tg, "%s: no connection", __func__);
		return 1;
	}
	ON_LOG(tg, "%s: got new auth key with len: %d and id: %ld", 
			__func__, tg->key.size, tg->key_id);

	// ask phone_number
	char * phone_number = 
			(char *)_TG_CB(tg, TG_AUTH_PHONE_NUMBER_NEEDED, NULL);
	
	if (!phone_number){
		ON_ERR(tg, "phone number is NULL");
		return 1;
	}
	ON_LOG(tg, "phone number: %s", phone_number);

	// send authorization code
	tl_auth_sentCode_t *sentCode = 
		tg_auth_sendCode(tg, phone_number);

	if (!sentCode)
		return 1;

	// ask user for code
	char *phone_code = 
		(char *)_TG_CB(tg, TG_AUTH_PHONE_CODE_NEEDED, sentCode);
	if (!phone_code){
		ON_ERR(tg, "phone code is NULL");
		return 1;
	}
	ON_LOG(tg, "phone code: %s", phone_code);

	// catch errors
	int err_code = 0;
	tl_auth_authorization_t *auth = tg_auth_signIn(tg, 
			sentCode, phone_number, phone_code, &err_code);

	if (auth){
		// authorized!
		_TG_CB(tg, TG_AUTH_NEW_AUTHORIZATION, auth);
		_TG_CB(tg, TG_AUTH_AUTHORIZED_AS_USER, auth->user_);
	}

	// check if need password
	switch (err_code) {
		case TG_SESSION_PASSWORD_NEEDED:
			{
				// ask user for password
				char *password = 
					(char *)_TG_CB(tg, TG_AUTH_PASSWORD_NEEDED, sentCode);
				if (!password){
					ON_ERR(tg, "password is NULL");
				}
				ON_LOG(tg, "password: %s", password);

				auth = tg_auth_check_password(tg, password);

				if (auth){
					// authorized!
					_TG_CB(tg, TG_AUTH_NEW_AUTHORIZATION, auth);
					_TG_CB(tg, TG_AUTH_AUTHORIZED_AS_USER, auth->user_);
					return 0;

				} else {
					ON_ERR(tg, "password is incorrect!");
					return 1;
				}

			}
			break;
		
		case TG_AUTH_RESTART:
			{
				_TG_CB(tg, TG_AUTH_RESTART, sentCode);
				// restart connection
				return tg_connect(tg);
			}
			break;

		case TG_PHONE_CODE_EXPIRED:
			{
				_TG_CB(tg, TG_PHONE_CODE_EXPIRED, sentCode);
				// restart connection
				return tg_connect(tg);
			}
			break;

		case TG_PHONE_NUMBER_UNOCCUPIED:
				_TG_CB(tg, TG_PHONE_NUMBER_UNOCCUPIED, sentCode);

		default:
			break;
			
	}

	return 1;
}
