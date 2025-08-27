#ifndef TG_H
#define TG_H 

#include <pthread.h>
#include "tg_log.h"
#include "../essential/buf.h"
#include "../essential/alloc.h"

#define SERVER_IP   "149.154.167.50"
//#define SERVER_IP   "149.154.175.57"
#define SERVER_PORT 443

struct tg_t {
	int id;
	int apiId;
	char apiHash[33];
	const char *pubkey;
	char ip[16];
	int port;
	int seqn;
	pthread_mutex_t seqnm;
	buf_t key;
	uint64_t key_id;
	buf_t salt;
	buf_t ssid;
	void *on_err_data;
	void (*on_err)(void *on_err_data, const char *err);
	void *on_log_data;
	void (*on_log)(void *on_log_data, const char *msg);
	void *on_update_data;
	void (*on_update)(void *on_update_data, int type, void *data);
	uint64_t *msgids; 
	pthread_mutex_t msgidsm;
	time_t timediff;
	uint64_t fingerprint;
};

#endif /* ifndef TG_H */
