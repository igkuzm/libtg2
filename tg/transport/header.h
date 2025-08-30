#ifndef TG_TRANSPORT_HEADER_H
#define TG_TRANSPORT_HEADER_H
#include "../../libtg.h"

extern buf_t tg_transport_pack(tg_t *tg, buf_t *query);
extern buf_t tg_transport_unpack(tg_t *tg, buf_t *answer);

#endif /* ifndef TG_TRANSPORT_HEADER_H */
