#ifndef TG_LOG_H
#define TG_LOG_H 

#include "../essential/str.h"

#define ON_CALLBACK(tg, type, data)\
	({ \
		void *ret = NULL; \
		if (tg->callback){ \
			ret = tg->callback(tg->userdata, type, data); \
		}\
		ret; \
	})

#define ON_ERR(tg, ...)\
	({ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		ON_CALLBACK(tg, TG_ERROR, _s.str); \
		free(_s.str);\
	})

#define ON_LOG(tg, ...)\
	({ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		ON_CALLBACK(tg, TG_LOG, _s.str); \
		free(_s.str);\
	})

#define ON_LOG_BUF(tg, buf, ...)\
	({ \
		struct str _s; str_init(&_s); str_appendf(&_s, __VA_ARGS__);\
		char *dump = buf_sdump(buf);\
		str_append(&_s, dump, strlen(dump));\
		free(dump);\
		ON_CALLBACK(tg, TG_LOG, _s.str); \
		free(_s.str);\
	 }\
	})

#endif /* ifndef TG_LOG_H */
