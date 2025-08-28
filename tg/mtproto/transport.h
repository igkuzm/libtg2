#ifndef TG_TRANSPORT_H
#define TG_TRANSPORT_H
#include "../../libtg.h"

extern buf_t tg_transport(tg_t *tg, buf_t buf);
extern buf_t tg_detransport(tg_t *tg, buf_t a);

#endif /* ifndef TG_TRANSPORT_H */
