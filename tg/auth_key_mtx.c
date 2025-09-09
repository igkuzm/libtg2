#include "auth_key_mtx.h"
#include "tg.h"
#include "tg_log.h"
#include "../mtx/include/api.h"
#include "crypto/hsh.h"

int tg_new_auth_key_mtx(tg_t *tg)
{
	net_t net = api.net.open(tg->dc.ipv4, tg->port);
  api.srl.init();
	ON_LOG(tg, "%s: >> auth", __func__);
  api.srl.auth();

	if (shared_rc.key.size){
		ON_LOG(tg, "%s: << key", __func__);
		
		tg->key = buf_add(
				shared_rc.key.data, shared_rc.key.size);

		buf_t key_hash = tg_hsh_sha1(tg->key);
		buf_t auth_key_id = 
			buf_add(key_hash.data + 12, 8);
		tg->key_id = buf_get_ui64(auth_key_id);
		buf_free(key_hash);
		buf_free(auth_key_id);

		tg->seqn = shared_rc.seqnh + 1;

		tg->socket = shared_rc.net.sockfd;

		tg->salt = buf_add( 
				shared_rc.salt.data, shared_rc.salt.size);

		// new session
		tg->ssid = buf_rand(8);

		return 0;
	}

	ON_ERR(tg, "%s: can't get new auth key", __func__);
	return -1;
}
