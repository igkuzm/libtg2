#include "mtproto.h"
#include "../tg.h"
#include "../tg_log.h"
#include "header.h"
#include "encrypt.h"
#include "ack.h"
#include "../../essential/ld.h"
#include "../strerr.h"

buf_t tg_mtproto_pack(
		tg_t *tg, buf_t *query, bool enc, uint64_t *msgid)
{
	ON_LOG(tg, "%s", __func__);
	
	buf_t header = tg_header(tg, query, enc, true, msgid);
	buf_t encrypt = tg_encrypt(tg, &header, enc);
	buf_free(header);

	return encrypt;
}

buf_t tg_mtproto_unpack(tg_t *tg, buf_t *answer, bool enc)
{
	ON_LOG(tg, "%s", __func__);
	
	buf_t decrypt = tg_decrypt(tg, answer, enc);
	buf_t payload = tg_deheader(tg, &decrypt, enc);
	buf_free(decrypt);

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
