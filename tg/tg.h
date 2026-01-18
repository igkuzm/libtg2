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
	int id;                    // id for multiple Telegram
	dc_t dc;                   // default dc - see dc.h
	int apiId;                 // apiId 
	char apiHash[33];          // apiHash
	const char *pubkey;        // pubkey pem
	const char *database_path; // filepath to database
	sqlite3 *db;
	int seqn;
	int socket;
	int port;                  // default port 
	pthread_mutex_t lock;      // lock libtg data
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
			               TG_CALLBACK_DATA_TYPE data_type,
										 void *data);
	TG_TRANSPORT transport;
};

void tg_auth_key_id_update(tg_t *);

#endif /* ifndef TG_H */
