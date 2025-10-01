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

#define _TG_CB(auth, tl, ...)\
	({\
	 char err[256];\
	 sprintf(err, __VA_ARGS__);\
	 char *ret = NULL;\
	 if (callback){\
		ret = callback(userdata, auth, (tl_t *)tl, err);\
	 }\
	 ret;\
	})

int tg_connect(
		tg_t *tg,
		void *userdata,
		char * (*callback)(
			void *userdata,
			TG_AUTH auth,
			const tl_t *tl,
			const char *error))
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
		_TG_CB(TG_AUTH_AUTHORIZED_AS_USER, user, "authorized!");
		return 0;
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
			_TG_CB(TG_AUTH_PHONE_NUMBER_NEEDED, NULL, 
					"enter phone number (+7XXXXXXXXXX)");
	
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
		_TG_CB(TG_AUTH_PHONE_CODE_NEEDED, sentCode, "enter code");
	if (!phone_code){
		ON_ERR(tg, "phone code is NULL");
		return 1;
	}
	ON_LOG(tg, "phone code: %s", phone_code);

	// catch errors
	AUTH_ERR_CODE err_code = AUTH_ERR_CODE_OK;
	tl_auth_authorization_t *auth = tg_auth_signIn(tg, 
			sentCode, phone_number, phone_code, &err_code);

	if (auth){
		// authorized!
		_TG_CB(TG_AUTH_NEW_AUTHORIZATION, auth, "authorization done");
		_TG_CB(TG_AUTH_AUTHORIZED_AS_USER, auth->user_, "authorized!");
		return 0;
	}

	// check if need password
	switch (err_code) {
		case SESSION_PASSWORD_NEEDED:
			{
				// ask user for password
				char *password = 
					_TG_CB(TG_AUTH_PASSWORD_NEEDED, sentCode, "enter password");
				if (!password){
					ON_ERR(tg, "password is NULL");
					return 1;
				}
				ON_LOG(tg, "password: %s", password);

				auth = tg_auth_check_password(tg, password);

				if (auth){
					// authorized!
					_TG_CB(TG_AUTH_NEW_AUTHORIZATION, auth, "authorization done");
					_TG_CB(TG_AUTH_AUTHORIZED_AS_USER, auth->user_, "authorized!");
					return 0;

				} else {
					_TG_CB(TG_AUTH_ERROR, sentCode, 
							"password is incorrect!");
					return 1;
				}

			}
			break;
		
		case AUTH_RESTART:
			{
				_TG_CB(TG_AUTH_ERROR, sentCode, "restart authorization!");
				// restart connection
				return tg_connect(tg, userdata, callback);
			}
			break;

		case PHONE_CODE_EXPIRED:
			{
				_TG_CB(TG_AUTH_ERROR, sentCode, "phone code expired!");
				// restart connection
				return tg_connect(tg, userdata, callback);
			}
			break;

		case PHONE_NUMBER_UNOCCUPIED:
				_TG_CB(TG_AUTH_ERROR, sentCode, 
						"phone number unoccupied! you need to create new account");

		default:
			break;
			
	}

	return 1;
}
