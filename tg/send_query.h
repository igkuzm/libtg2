#ifndef TG_SEND_QUERY_H
#define TG_SEND_QUERY_H
#include "../libtg.h"
#include "transport/progress.h"
#include "dc.h"

extern tl_t *tg_send_rfc(tg_t *tg, buf_t *query); 

extern void tg_send_query(tg_t *, buf_t *query);

extern tl_t *tg_send_query_sync(tg_t *tg, buf_t *query); 

extern void tg_send_query_async(tg_t *tg, buf_t *query, 
	void *userdata, 
	int tg_get_dialogs_callback(void *userdata, const tl_t *tl)); 

extern tl_t *tg_file_transfer(
		tg_t *tg, buf_t *query, enum dc, 
		void *progressp, tg_progress_fun *progress);

#endif /* ifndef TG_SEND_QUERY_H */
