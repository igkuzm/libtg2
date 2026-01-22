#ifndef TG_DATABASE_H
#define TG_DATABASE_H
#include "../tg.h"
#include <sqlite3.h>

int tg_database_init(tg_t *tg);
int tg_database_close(tg_t *tg);

int tg_sqlite3_prepare(
		tg_t *tg, const char *sql, sqlite3_stmt **stmt);

#define tg_sqlite3_for_each(tg, sql, stmt) \
	sqlite3_stmt *stmt;\
	int sqlite_step;\
	if (tg_sqlite3_prepare(tg, sql, &stmt) == 0)\
		for (sqlite_step = sqlite3_step(stmt);\
				sqlite_step	!= SQLITE_DONE || ({sqlite3_finalize(stmt); 0;});\
				sqlite_step = sqlite3_step(stmt))\
			 
#define tg_do_in_database_lock(tg) \
	sqlite3_mutex *mutex;\
	for(mutex = sqlite3_db_mutex(tg->db), sqlite3_mutex_enter(mutex); \
			mutex; \
			sqlite3_mutex_leave(mutex), mutex = NULL)

#endif /* ifndef TG_DATABASE_H */
