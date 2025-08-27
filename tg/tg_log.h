#ifndef TG_LOG_H
#define TG_LOG_H 

#include "../essential/str.h"

#define ON_UPDATE(tg, type, data)\
	({if (tg->on_update){ \
		tg->on_update(tg->on_update_data, type, data); \
	 }\
	})

#define ON_ERR(tg, ...)\
	({if (tg->on_err){ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		tg->on_err(tg->on_err_data, _s.str); \
		free(_s.str);\
	 }\
	})

#define ON_LOG(tg, ...)\
	({if (tg->on_log){ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		tg->on_log(tg->on_log_data, _s.str); \
		free(_s.str);\
	 }\
	})

#define ON_LOG_BUF(tg, buf, ...)\
	({if (tg->on_log){ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		char *dump = buf_sdump(buf);\
		str_append(&_s, dump, strlen(dump));\
		free(dump);\
		tg->on_log(tg->on_log_data, _s.str); \
		free(_s.str);\
	 }\
	})

#endif /* ifndef TG_LOG_H */
