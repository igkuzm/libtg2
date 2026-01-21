#ifndef TG_H
#define TG_H 

#include <pthread.h>
#include <sqlite3.h>
#include "tg_log.h"
#include "dc.h"
#include "../essential/buf.h"
#include "../essential/alloc.h"
#include "../libtg.h"

/*#define DEFAULT_DC   DC2t*/
#define DEFAULT_DC   DC2
#define DEFAULT_PORT 443
#define DEFAULT_TRANSPORT TG_TRANSPORT_SOCKET

struct tg_t {
	int id;                      // id for multiple Telegram
	dc_t dc;                     // default dc - see dc.h
	int apiId;                   // apiId 
	char apiHash[33];            // apiHash
	const char *pubkey;          // pubkey pem
	const char *database_path;   // filepath to database
	sqlite3 *db;
	int seqn;
	int socket;
	int port;                    // default port 
	pthread_mutex_t lock;        // lock libtg data
	pthread_mutex_t lock_msgids; 
	pthread_mutex_t lock_todrop; 
	pthread_mutex_t lock_seqn; 
	buf_t key;
	uint64_t key_id;
	buf_t salt;
	buf_t ssid;
	uint64_t *msgids; 
	uint64_t *todrop; 
	time_t timediff;
	uint64_t fingerprint;
	tl_config_t *config;
	tl_user_t *user;
	void *userdata;
	void * (*callback)(void *userdata,
			               int data_type,
										 void *data);
	TG_TRANSPORT transport;
};

void tg_auth_key_id_update(tg_t *);

enum mutex_lock {
	TG_MUTEX_LOCK,
	TG_MUTEX_LOCK_MSGIDS,
	TG_MUTEX_LOCK_TODROP,
	TG_MUTEX_LOCK_SEQN,
};

static int tg_mutex_lock_parse_error(
		tg_t *tg, int err, enum mutex_lock lock)
{
	if (err){
		char *mutex_lock = (char *)"TG";
		switch (lock) {
			case TG_MUTEX_LOCK_MSGIDS:
				mutex_lock = (char *)"MSGIDS";
				break;
			case TG_MUTEX_LOCK_TODROP:
				mutex_lock = (char *)"TODROP";
				break;
			case TG_MUTEX_LOCK_SEQN:
				mutex_lock = (char *)"SEQN";
				break;

			default:
				break;
		}
		ON_ERR(tg, "Can't lock mutex %s: %d", mutex_lock, err);
	}	
	return 0;
}

#define tg_do_in_mutex_locked(_tg, _m, _ml) \
	int _locked, _error; \
	for (_locked = (_error = pthread_mutex_lock(_m) == 0); \
			 _locked || tg_mutex_lock_parse_error(_tg, _error, _ml); \
			 pthread_mutex_unlock(_m), _locked = 0)

#define tg_do_in_msgids_locked(tg) \
	tg_do_in_mutex_locked(tg, &tg->lock_msgids, TG_MUTEX_LOCK_MSGIDS)

#define tg_do_in_todrop_locked(tg) \
	tg_do_in_mutex_locked(tg, &tg->lock_todrop, TG_MUTEX_LOCK_TODROP)

#define tg_do_in_seqn_locked(tg) \
	tg_do_in_mutex_locked(tg, &tg->lock_seqn, TG_MUTEX_LOCK_SEQN)

#endif /* ifndef TG_H */
