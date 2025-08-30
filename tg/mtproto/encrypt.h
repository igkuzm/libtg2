#ifndef TG_ENCRYPT
#define TG_ENCRYPT
#include "../../libtg.h"

extern buf_t tg_encrypt(tg_t *tg, buf_t *b, bool encypt);

extern buf_t tg_decrypt(tg_t *tg, buf_t *m, bool encypted);

#endif /* ifndef TG_ENCRYPT */
