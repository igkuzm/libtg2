#ifndef TG_ACK_H
#define TG_ACK_H
#include "../../libtg.h"

extern void tg_add_msgid(tg_t *tg, uint64_t msgid);
extern buf_t tg_ack(tg_t *tg);

#endif /* ifndef TG_ACK_H */
