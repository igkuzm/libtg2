#ifndef LIBTG_H
#define LIBTG_H

#include "essential/buf.h"
#include  "tl/libtl.h"
#include "tl/struct.h"

// LibTG structure
typedef struct tg_t tg_t;

typedef enum {
	TG_NULL,
	TG_LOG,
	TG_ERROR,
	TG_AUTH_PHONE_NUMBER_NEEDED,
	TG_AUTH_PHONE_CODE_NEEDED,
	TG_AUTH_PASSWORD_NEEDED,
	TG_AUTH_NEW_AUTHORIZATION,
	TG_AUTH_AUTHORIZED_AS_USER,
	TG_AUTH_RESTART,
	TG_PHONE_CODE_EXPIRED,
	TG_PHONE_NUMBER_UNOCCUPIED,
	TG_SESSION_PASSWORD_NEEDED,
} TG_CALLBACK_DATA_TYPE;

/* create new libtg connection */
tg_t * tg_new(
		int apiId, 
		const char apiHash[33], 
		const char *pubkey_pem,
		const char *database_path,
		unsigned char *auth_key,
		void *userdata,
		void * (*callback)(void *userdata,
			                 int data_type,
											 void *data));

int tg_connect(tg_t *tg); // connect Telegram
unsigned char * tg_auth_key(tg_t *tg); // get auth_key
void tg_update(tg_t *tg);  // update dialogs from server

/* free libtg structure and free memory */
void tg_close(tg_t *);

/* get NULL-terminated auto-free dialogs array - full list 
 * of chats with messages and auxilary data */
void tg_get_dialogs(tg_t *tg, 
		uint32_t *folder_id, 
		uint32_t offset_date, int limit, 
		void *userdata, 
		void (*callback)(void *userdata, tl_t **dialogs));

/* get NULL-terminated auto-free messages array */
void tg_get_messages(tg_t *tg, 
		int nids, uint32_t *ids,
		void *userdata, 
		void (*callback)(void *userdata, tl_t **messages));

/* get NULL-terminated auto-free chats array */
void tg_get_chats(tg_t *tg, 
		int nids, uint32_t *ids,
		void *userdata, 
		void (*callback)(void *userdata, tl_t **chats));

/* get NULL-terminated auto-free users array */
void tg_get_users(tg_t *tg, 
		int nids, uint32_t *ids,
		void *userdata, 
		void (*callback)(void *userdata, tl_t **chats));


/* functions to help parse tl_messages_dialogs_t and get
 * peer. Peer is chat, channel or user dialog */
typedef enum {
	TG_PEER_NULL,
	TG_PEER_USER,
	TG_PEER_CHANNEL,
	TG_PEER_CHAT,
} TG_PEER;

typedef struct tg_peer_ {
	TG_PEER type;
	const char *title;
	tl_t *tl;
} tg_peer_t;

tg_peer_t tg_dialogs_get_peer(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, int idx);

tg_peer_t tg_dialogs_get_peer_with_peer_id(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, uint64_t id);

/* function to help parse tl_messages_dialogs_t and get
 * message */
typedef struct tg_message_ {
	tg_peer_t from;
	tl_message_t *msg;
} tg_message_t;

tg_message_t tg_dialogs_get_dialog_top_message(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, int idx);

/* MESSAGES */
tg_peer_t tg_message_get_peer(
		tg_t *tg, const tl_messages_dialogs_t *dialogs, int idx);

typedef enum {
	TG_TRANSPORT_HTTP,
	TG_TRANSPORT_SOCKET,
} TG_TRANSPORT;

/* set default transport */
void tg_set_transport(tg_t *, TG_TRANSPORT);

#endif /* ifndef LIBTG_H */
