#ifndef TG_HTTP_H
#define TG_HTTP_H value

#include "../../libtg.h"
#include "progress.h"

/* send buf_t data and rescive answer */
extern buf_t tg_http_transport(
		tg_t *tg, int dc, int port, bool maximum_limit, 
		bool test, buf_t data,
		void *progressp, 
		tg_progress_fun *progress);

#endif /* ifndef TG_HTTP_H */
