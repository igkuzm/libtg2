#ifndef TG_AUTH_H
#define TG_AUTH_H
#include "../libtg.h"

tl_auth_sentCode_t *
tg_auth_sendCode(tg_t *tg, const char *phone_number,
		int ntokens, char *logout_tokens[]); 

#endif /* ifndef TG_AUTH_H */
