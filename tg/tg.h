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

#define tg_do_in_mutex_locked(_tg, _m, _on_error) \
	int _m_error = pthread_mutex_lock(_m); \
	if (_m_error) { \
		ON_ERR(_tg, "%s: can't lock mutex: %d", __func__, _m_error); \
		_on_error; \
	} \
	for (; \
			 _m_error == 0; \
			 pthread_mutex_unlock(_m), _m_error = 1)

#define tg_do_in_msgids_locked(tg, ...) \
	tg_do_in_mutex_locked(tg, &tg->lock_msgids, __VA_ARGS__)

#define tg_do_in_todrop_locked(tg, ...) \
	tg_do_in_mutex_locked(tg, &tg->lock_todrop, __VA_ARGS__)

#define tg_do_in_seqn_locked(tg, ...) \
	tg_do_in_mutex_locked(tg, &tg->lock_seqn, __VA_ARGS__)

#endif /* ifndef TG_H */
