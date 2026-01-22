#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"
#include "../crypto/hsh.h"
#include "../../essential/ld.h"

sqlite3 * tg_sqlite3_open(tg_t *tg) 
{
	ON_LOG(tg, "%s", __func__);
	assert(tg->database_path);

	int err = sqlite3_open_v2(
			tg->database_path,
		 	&tg->db, 
			SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_CREATE, 
			NULL);
	if (err){
		ON_ERR(tg, "%s: %s", __func__, (char *)sqlite3_errmsg(tg->db));
		return NULL;
	}

	if (tg->db == NULL)
		ON_ERR(tg, "%s: can't init database", __func__);

	return tg->db;
}

int tg_sqlite3_prepare(
		tg_t *tg, const char *sql, sqlite3_stmt **stmt) 
{
	ON_LOG(tg, "%s", __func__);
	int res = sqlite3_prepare_v2(
			tg->db, 
			sql, 
			-1, 
			stmt,
		 	NULL);
	if (res != SQLITE_OK){
		// parse error
		ON_ERR(tg, "%s: %s", __func__, sqlite3_errmsg(tg->db));
		return 1;
	}	

	return 0;
}

int tg_sqlite3_exec(
		tg_t *tg, const char *sql) 
{
	ON_LOG(tg, "%s", __func__);
	char *errmsg = NULL;

	int res = 
		sqlite3_exec(tg->db, sql, NULL, NULL, &errmsg);
	if (errmsg){
		// parse error
		ON_ERR(tg, "%s: %s", __func__, errmsg);
		sqlite3_free(errmsg);	
		return 1;
	}	
	if (res != SQLITE_OK){
		// parse error
		ON_ERR(tg, "%s: %s", __func__, sqlite3_errmsg(tg->db));
		return 1;
	}

	return 0;
}

static void tg_databae_create_dialogs_table(tg_t *tg){
	char sql[] = 
			"CREATE TABLE IF NOT EXISTS dialogs ("
			"peer_id INT UNIQUE, "
			"pinned INT, "
			"top_message_id INT, "
			"top_message_date INT, "
			"folder_id INT, "
			"data BLOB);";
	ON_LOG(tg, "%s", sql);
	tg_sqlite3_exec(tg, sql);	
}

static void tg_databae_create_messages_table(tg_t *tg){
	char sql[] = 
			"CREATE TABLE IF NOT EXISTS messages ("
			"id INT UNIQUE, "
			"message_date INT, "
			"data BLOB);";
	ON_LOG(tg, "%s", sql);
	tg_sqlite3_exec(tg, sql);	
}

int tg_database_close(tg_t *tg)
{
	sqlite3_close(tg->db);
	return 0;
}

int tg_database_init(tg_t *tg)
{
	ON_LOG(tg, "%s", __func__);	
	if(tg_sqlite3_open(tg) == NULL)
		return 1;

	/*tg_sqlite3_exec(tg, "PRAGMA journal_mode = wal;");*/
	/*tg_sqlite3_exec(tg, "PRAGMA busy_timeout = 5000;");*/

	// create tables
	tg_databae_create_dialogs_table(tg);
	tg_databae_create_messages_table(tg);

	//tg_chats_create_table(tg);
	//tg_users_create_table(tg);
	
	return 0;
}


