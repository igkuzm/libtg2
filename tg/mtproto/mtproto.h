#ifndef TG_MTPROTO_H
#define TG_MTPROTO_H
#include "../../libtg.h"

extern buf_t tg_mtproto_pack(
		tg_t *tg, buf_t *query, bool enc, uint64_t *msgid);

extern buf_t tg_mtproto_unpack(
		tg_t *tg, buf_t *answer, bool enc);

extern tl_t *tg_mtproto_guzip(tg_t *tg, tl_t *tl);

#endif /* ifndef TG_MTPROTO_H */
