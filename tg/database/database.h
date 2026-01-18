#ifndef TG_DATABASE_H
#define TG_DATABASE_H
#include "../tg.h"

int tg_database_init(tg_t *tg);
int tg_database_close(tg_t *tg);
int tg_database_authkey_load(tg_t *tg);
int tg_database_authkey_save(tg_t *tg);

#endif /* ifndef TG_DATABASE_H */
