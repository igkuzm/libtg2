#ifndef TG_SEND_QUERY_H
#define TG_SEND_QUERY_H
#include "../libtg.h"
#include "transport/progress.h"

extern void tg_send_query(
		tg_t *tg, buf_t *query, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl));

extern void tg_send_query_with_progress(
		tg_t *tg, buf_t *query, int dc, 
		void *ptr, int (*callback)(void *ptr, const tl_t *tl),
		void *progressp, tg_progress_fun *progress);

#endif /* ifndef TG_SEND_QUERY_H */
