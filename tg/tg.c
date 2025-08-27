#include "tg.h"
#include "../libtg.h"
#include "crypto/hsh.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

tg_t *tg_new(
		int apiId, 
		const char apiHash[33], 
		const char *pem,
		unsigned char *auth_key
		)
{
	// allocate struct
	tg_t *tg = NEW(tg_t, return NULL);	

	// set apiId and apiHash
	tg->apiId = apiId;
	strncpy(tg->apiHash, apiHash, 33);

	// set public_key
	tg->pubkey = pem;

	// set server address
	strncpy(tg->ip, SERVER_IP,
		sizeof(tg->ip) - 1);
	
	// set port
	tg->port = SERVER_PORT;

	// set auth_key
	if (auth_key){
		tg->key = buf_add(auth_key, 64);
		// auth key id
		buf_t key_hash = tg_hsh_sha1(tg->key);
		buf_t auth_key_id = 
			buf_add(key_hash.data + 12, 8);
		tg->key_id = buf_get_ui64(auth_key_id);
		buf_free(key_hash);
		buf_free(auth_key_id);
	}

	// start new seqn
	tg->seqn = 0;

	if (pthread_mutex_init(
				&tg->msgidsm, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		return NULL;
	}

	if (pthread_mutex_init(
				&tg->seqnm, NULL))
	{
		ON_ERR(tg, "%s: can't init mutex", __func__);
		return NULL;
	}

	return tg;
}

void tg_close(tg_t *tg)
{
	// close Telegram
	/* TODO:  <28-08-25, yourname> */
	
	// free
	free(tg);
}

void tg_set_on_error(tg_t *tg,
		void *on_err_data,
		void (*on_err)(void *on_err_data, const char *err))
{
	if (tg){
		tg->on_err = on_err;
		tg->on_err_data = on_err_data;
	}
}

void tg_set_on_log(tg_t *tg,
		void *on_log_data,
		void (*on_log)(void *on_log_data, const char *msg))
{
	if (tg){
		tg->on_log = on_log;
		tg->on_log_data = on_log_data;
	}
}

void tg_set_on_update(tg_t *tg,
		void *on_update_data,
		void (*on_update)(void *on_update_data, int type, void *data))
{
	if (tg){
		tg->on_update = on_update;
		tg->on_update_data = on_update_data;
	}
}

void tg_set_server_address(tg_t *tg, const char *ip, int port)
{
	if (tg){
		strncpy(tg->ip, ip,
			 	sizeof(tg->ip) - 1);
		tg->port = port;
	}
}
