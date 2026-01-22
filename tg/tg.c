#include "tg.h"
#include "../libtg.h"
#include "crypto/hsh.h"
#include "tg_log.h"
#include "database/database.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../essential/ld.h"

tg_t * tg_new(
		int apiId, 
		const char apiHash[33], 
		const char *pubkey_pem,
		const char *database_path,
		unsigned char *auth_key,
		void *userdata,
		void * (*callback)(void *userdata,
			                 int data_type,
											 void *data))
{
	// allocate struct
	tg_t *tg = NEW(tg_t, return NULL);	
	tg->userdata = userdata;
	tg->callback = callback;
	
	// set apiId and apiHash
	tg->apiId = apiId;
	strncpy(tg->apiHash, apiHash, 33);

	// init database
	tg->database_path = database_path;
	if (tg_database_init(tg))
		goto tg_new_error;

	// check pem
	FILE *fp = fopen(pubkey_pem, "r");
	if (!fp){
		ON_ERR(tg, "can't open public key");
		goto tg_new_error;
	}
	fclose(fp);

	tg->dc = DCs[DEFAULT_DC];

	tg->socket = -1;
	tg->port = DEFAULT_PORT;
	tg->transport = DEFAULT_TRANSPORT;

	// set public_key
	tg->pubkey = pubkey_pem;

	// set auth_key
	if (auth_key){
		tg->key = buf_new_data(auth_key, 256);
		tg_auth_key_id_update(tg);
	} else
		tg->key = buf_new();
	
	tg->ssid = buf_new_rand(8);
	tg->salt = buf_new_rand(8);

	// start new seqn
	tg->seqn = 0;

	if (pthread_mutex_init(
				&tg->lock, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		goto tg_new_error;
	}
	
	if (pthread_mutex_init(
				&tg->lock_msgids, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		goto tg_new_error;
	}

	if (pthread_mutex_init(
				&tg->lock_todrop, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		goto tg_new_error;
	}

	if (pthread_mutex_init(
				&tg->lock_seqn, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		goto tg_new_error;
	}

	return tg;

tg_new_error:
	free(tg);
	return NULL;
}

void tg_close(tg_t *tg)
{
	// close Telegram
	/* TODO:  <28-08-25, yourname> */
	
	// free
	free(tg);
}

void tg_auth_key_id_update(tg_t *tg)
{
	buf_t key_hash = tg_hsh_sha1(tg->key);
	buf_t auth_key_id = 
		buf_new_data(key_hash.data + 12, 8);
	tg->key_id = buf_get_ui64(auth_key_id);
	buf_free(key_hash);
	buf_free(auth_key_id);
	ON_LOG(tg, "%s: key_id: "_LX_"", __func__, tg->key_id);
}

void tg_set_transport(tg_t *tg, TG_TRANSPORT transport)
{
	tg->transport = transport;
}

void tg_update(tg_t *tg)
{
	uint32_t top_message_date = 
		tg_dialogs_get_top_message_date(tg);

	tg_dialogs_update(tg, 0, top_message_date,
		 	NULL);
}

unsigned char * tg_auth_key(tg_t *tg)
{
	return tg->key.data;
}


