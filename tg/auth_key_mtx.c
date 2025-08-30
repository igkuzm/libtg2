#include "auth_key_mtx.h"
#include "tg.h"
#include "tg_log.h"
#include "../mtx/include/api.h"

int tg_new_auth_key_mtx(tg_t *tg)
{
	net_t net = api.net.open(tg->dc.ipv4, tg->port);
  api.srl.init();
	ON_LOG(tg, "%s: >> auth", __func__);
  api.srl.auth();
	api.net.close(net);

	if (shared_rc.key.size){
		ON_LOG(tg, "%s: << key", __func__);
		tg->key = buf_cat_data(tg->key, 
				shared_rc.key.data, shared_rc.key.size);
		return 0;
	}

	ON_ERR(tg, "%s: can't get new auth key", __func__);
	return -1;
}
