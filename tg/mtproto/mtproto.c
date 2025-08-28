#include "mtproto.h"
#include "../tg.h"
#include "../tg_log.h"
#include "header.h"
#include "encrypt.h"
#include "transport.h"
#include "ack.h"
#include "../../essential/ld.h"
#include "../strerr.h"

buf_t tg_mtproto_transport(
		tg_t *tg, buf_t *query, bool enc, 
		TG_TRANSPORT transport,
		uint64_t *msgid)
{
	ON_LOG(tg, "%s", __func__);
	
	buf_t h = tg_header(tg, *query, enc, true, msgid);
				
	buf_t e = tg_encrypt(tg, h, enc);
	buf_free(h);

	if (transport == TG_TRANSPORT_HTTP)
		return e;

	buf_t t = tg_transport(tg, e);
	buf_free(e);

	return t;
}

buf_t tg_mtproto_detransport(
		tg_t *tg, buf_t *answer, bool enc,
		TG_TRANSPORT transport)
{
	ON_LOG(tg, "%s", __func__);
	
	buf_t e;
	if (transport == TG_TRANSPORT_HTTP){
		e = tg_decrypt(tg, *answer, enc);

	} else {
		buf_t t = tg_detransport(tg, *answer);

		buf_t e = tg_decrypt(tg, t, enc);
		buf_free(t);
	}

	buf_t payload = tg_deheader(tg, e, enc);
	buf_free(e);

	return payload;
}

tl_t *tg_mtproto_guzip(tg_t *tg, tl_t *tl)
{
	if (tl == NULL){
		ON_ERR(tg, "%s: tl is NULL", __func__);
		return NULL;
	}

	if (tl->_id != id_gzip_packed){
		ON_ERR(tg, "%s: is not GZIP", __func__);
		return NULL;
	}

	// handle gzip
	tl_gzip_packed_t *gzip =
		(tl_gzip_packed_t *)tl;

	buf_t buf;
	int _e = 
		gunzip_buf(&buf, gzip->packed_data_);
	if (_e) {
		char *err = gunzip_buf_err(_e);
		ON_ERR(tg, "%s: %s", __func__, err);
		free(err);
	} else {
		tl_t *tl = tl_deserialize(&buf);
		buf_free(buf);
		return tl;
	}

	return NULL;
}
