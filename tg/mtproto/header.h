#ifndef TG_HEADER_H
#define TG_HEADER_H
#include "../../libtg.h"

extern buf_t tg_header(tg_t *tg, buf_t *query, bool enc, 
		bool content, uint64_t *msgid);

extern buf_t tg_deheader(tg_t *tg, buf_t *answer, bool enc);

#endif /* ifndef TG_HEADER_H */
