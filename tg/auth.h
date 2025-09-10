#ifndef TG_AUTH_H
#define TG_AUTH_H
#include "../libtg.h"

tl_user_t *tg_is_authorized(tg_t *tg);

tl_auth_sentCode_t *
tg_auth_sendCode(tg_t *tg, const char *phone_number);

tl_auth_authorization_t *
tg_auth_signIn(tg_t *tg, tl_auth_sentCode_t *sentCode, 
		const char *phone_number, const char *phone_code); 

tl_auth_authorization_t *
tg_auth_check_password(tg_t *tg, const char *password);

#endif /* ifndef TG_AUTH_H */
