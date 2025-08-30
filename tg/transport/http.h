#ifndef TG_HTTP_H
#define TG_HTTP_H value

#include "../../libtg.h"
#include "progress.h"
#include "../dc.h"
#include <curl/curl.h>

/* send buf_t data and rescive answer */
extern buf_t tg_http_send_query(
		tg_t *tg, enum dc, int port, bool maximum_limit, 
		bool test, buf_t *query,
		void *progressp, 
		tg_progress_fun *progress);

#endif /* ifndef TG_HTTP_H */
