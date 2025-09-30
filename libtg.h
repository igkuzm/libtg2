#ifndef LIBTG_H
#define LIBTG_H

#include "essential/buf.h"
#include  "tl/libtl.h"
#include "tl/struct.h"

// LibTG structure
typedef struct tg_t tg_t;

/* create new libtg object */
tg_t * tg_new(
		int apiId, 
		const char apiHash[33], 
		const char *pubkey_pem,
		unsigned char *auth_key_or_null
		);

typedef enum {
	TG_TRANSPORT_HTTP,
	TG_TRANSPORT_SOCKET,
} TG_TRANSPORT;

/* set default transport */
void tg_set_transport(tg_t *, TG_TRANSPORT);

/* set on_error callback */
void tg_set_on_error(tg_t *tg,
		void *on_err_data,
		void (*on_err)(void *on_err_data, const char *err));

/* set on_log callback */
void tg_set_on_log(tg_t *tg,
		void *on_log_data,
		void (*on_log)(void *on_log_data, const char *msg));

/* free libtg structure and free memory */
void tg_close(tg_t *);

/* get 256-byte (2048-bit) auth_key */
unsigned char * tg_auth_key(tg_t *);

typedef enum {
	TG_AUTH_ERROR,
	TG_AUTH_PHONE_NUMBER_NEEDED,
	TG_AUTH_PHONE_CODE_NEEDED,
	TG_AUTH_PASSWORD_NEEDED,
	TG_AUTH_NEW_AUTHORIZATION,
	TG_AUTH_AUTHORIZED_AS_USER,
} TG_AUTH;

/* connect to Telegram */  
int tg_connect(
		tg_t *tg,
		void *userdata,
		char * (*callback)(
			void *userdata,
			TG_AUTH auth,
			const tl_t *tl,
			const char *msg));

/* set callback to handle telegram update information */
void tg_set_on_update(tg_t *tg,
		void *on_update_data,
		void (*on_update)(void *on_update_data, int type, void *data));

/* get dialogs - full list of chats with messages and
 * auxilary data
 * limit = -1 - to load all dialogs */
void tg_get_dialogs(
		tg_t *tg, 
		int limit, 
		uint32_t offset_date, 
		uint64_t * hash, 
		uint32_t * folder_id, 
		void *data,
		int (*callback)(void *data, const tl_messages_dialogs_t *dialogs));

#endif /* ifndef LIBTG_H */
