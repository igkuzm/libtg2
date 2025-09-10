#include "auth_key_mtx.h"
#include "send_query.h"
#include "tg.h"
#include "../essential/strtok_foreach.h"
#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "tg_log.h"
#include "transport/socket.h"

struct tg_connect_t {
	void *on_err_data;
	void (*on_err)(void *on_err_data, const char *err);
	char error[BUFSIZ];
};

void catch_errors(void *data, const char *err)
{
	struct tg_connect_t *t = (struct tg_connect_t *)data;
	strncpy(t->error, err, BUFSIZ - 1);
	t->error[BUFSIZ - 1] = 0;
	if (t->on_err)
		t->on_err(t->on_err_data, err);
}

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
	struct tg_connect_t t = 
		{tg->on_err_data, tg->on_err, 0};

	// check if authorized
	tl_user_t *user = tg_is_authorized(tg);
	if (user){
		_TG_CB(TG_AUTH_SUCCESS, user, "authorized!");
		return 0;
	}

	// get new auth key
	if (tg_new_auth_key_mtx(tg)){
		ON_ERR(tg, "no connection");
		return 1;
	}

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
	tg_set_on_error(tg, &t, catch_errors);

	tl_auth_authorization_t *auth = 
		tg_auth_signIn(tg, sentCode, phone_number, phone_code);

	// stop catch errors
	tg_set_on_error(tg, t.on_err_data, t.on_err);

	if (auth){
		// authorized!
		_TG_CB(TG_AUTH_AUTHORIZATION, auth, "authorization done");
		_TG_CB(TG_AUTH_SUCCESS, auth->user_, "authorized!");
		return 0;
	}

	// check if need password
	if (strcmp(t.error, "SESSION_PASSWORD_NEEDED") == 0)
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

		ON_ERR(tg, 
				"password auth is not implyed yet!");
		return 1;
	}

	/* TODO: AUTH_RESTART, PHONE_CODE_EXPIRED, 
	 * PHONE_NUMBER_UNOCCUPIED */

	return 1;
}
