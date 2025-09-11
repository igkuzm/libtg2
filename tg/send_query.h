#ifndef TG_SEND_QUERY_H
#define TG_SEND_QUERY_H
#include "../libtg.h"
#include "transport/progress.h"
#include "dc.h"

extern void tg_send_query(
		tg_t *tg, buf_t *query, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl));

extern tl_t *tg_send_query_sync(
		tg_t *tg, buf_t *query); 

extern void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, enum dc, bool enc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress);

#endif /* ifndef TG_SEND_QUERY_H */
