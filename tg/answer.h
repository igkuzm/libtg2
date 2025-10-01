#ifndef TG_ANSWER_H
#define TG_ANSWER_H
#include "../libtg.h"

typedef enum {
	TG_ANSWER_OK,
	TG_ANSWER_ERR,
	TG_ANSWER_RESEND_QUERY,
	TG_ANSWER_READ_AGAIN,
} TG_ANSWER;

extern TG_ANSWER tg_parse_answer(tg_t *tg, tl_t *tl, uint64_t msg_id,
		void *ptr, int (*callback)(void *ptr, const tl_t *tl));

#endif /* ifndef TG_ANSWER_H */
