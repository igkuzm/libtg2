#include "libtg.h"
#include "tg/auth_key_mtx.h"
#include "tg/auth_key1.h"
#include "tg/auth.h"
#include "tg/tg.h"
#include "api_id.h"
#include "tg/tg_log.h"

void on_log(void *d, const char *msg){
	printf("%s\n", msg);
}

int main(int argc, char *argv[])
{
	int SETUP_API_ID(apiId)
	char * SETUP_API_HASH(apiHash)

	tg_t *tg = tg_new(apiId, apiHash, 
			"pub.pkcs", NULL);
	if (!tg)
		return 1;

	tg_set_on_error(tg, NULL, on_log);
	tg_set_on_log(tg, NULL, on_log);

	printf("get new auth key\n");
	tg_new_auth_key_mtx(tg);
	/*tg_new_auth_key1(tg);*/
	
	ON_LOG(tg, "%s", "SEND CODE>>>>>>>>>>>>");
	tg_auth_sendCode(tg, "+79990407731",
		 	0, NULL);
	
	return 0;
}
