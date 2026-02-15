#include "libtg.h"
#include "tg/auth_key_mtx.h"
#include "tg/auth_key1.h"
#include "tg/auth_key2.h"
#include "tg/auth.h"
#include "tg/tg.h"
#include "api_id.h"
#include "tg/tg_log.h"
#include "tl/id.h"
#include <stdio.h>

void on_log(void *d, const char *msg){
	printf("%s\n", msg);
}

void * callback(
			void *userdata,
			int data_type,
			void *data)
{
	switch (data_type) {
		case TG_AUTH_PHONE_NUMBER_NEEDED:
			{
				char phone[32];
				printf("enter phone number (+7XXXXXXXXXX): \n");
				scanf("%s", phone);
				return strdup(phone);
			}
			break;
		case TG_AUTH_PHONE_CODE_NEEDED:
			{
				tl_auth_sentCode_t *sentCode =
					(tl_auth_sentCode_t *)data;
				
				char *type = NULL;
				switch (sentCode->type_->_id) {
					case id_auth_sentCodeTypeFlashCall:
						type = "FlashCall";
						break;
					case id_auth_sentCodeTypeApp:
						type = "Application";
						break;
					case id_auth_sentCodeTypeCall:
						type = "Call";
						break;
					case id_auth_sentCodeTypeMissedCall:
						type = "MissedCall";
						break;
					case id_auth_sentCodeTypeEmailCode:
						type = "Email";
						break;
					
					default:
						break;
				}

				int code;
				printf("The code was send via %s\n", type);
				printf("enter code: \n");
				scanf("%d", &code);
				printf("code: %d\n", code);
				char phone_code[32];
				sprintf(phone_code, "%d", code);
				return strdup(phone_code);
			}
			break;
		case TG_AUTH_PASSWORD_NEEDED:
			{
				char password[64];
				printf("enter password: \n");
				scanf("%s", password);
				printf("password: %s\n", password);
				return strdup(password);
			}
			break;
		case TG_AUTH_AUTHORIZED_AS_USER:
			{
				printf("Connected as ");
				tl_user_t *user = (tl_user_t *)data;
				printf("%s (%s)!\n", 
						(char *)user->username_.data, 
						(char *)user->phone_.data);
				
				FILE *fp = fopen("key", "w");
				if (fp){
					tg_t *tg = userdata;
					unsigned char *key = tg_auth_key(tg);
					fwrite(key, 256, 1, fp);
					fclose(fp);
				}

			}
			break;

		case TG_LOG:
			{
				if (data)
					printf("%s\n", (char *)data);
			}
			break;

		case TG_ERROR:
			{
				if (data)
					printf("\x1B[31mERROR!: %s\x1B[0m\n", (char *)data);
			}
			break;

		default:
			break;
	}

	return NULL;
}

//int dialogs_callback(void *userdata, const tl_messages_dialogs_t *md)
//{
	//tg_t *tg = userdata;
	//int i;
	//for (i = 0; i < md->dialogs_len; ++i) {
		//tg_peer_t peer = tg_dialogs_get_peer(tg, md, i);
		//tg_message_t msg = tg_dialogs_get_dialog_top_message(tg, 
				//md, i);
		//printf("%d: %s: %s: %20s\n\n", i, peer.title,
			 //msg.from.title,	
				//msg.msg->message_.data);
	//}

	//return 0;
//}

int main(int argc, char *argv[])
{
	int SETUP_API_ID(apiId)
	char * SETUP_API_HASH(apiHash)

	unsigned char key[256] = {0};
	FILE *fp = fopen("key", "r");
	if (fp){
		fread(key, 256, 1, fp);
		fclose(fp);
	}

	tg_t *tg = tg_new(apiId, apiHash, 
			"pub.pkcs", "libtg.db", 
			key[0]?key:NULL, NULL, callback);
	if (!tg)
		return 1;
	
	if (tg_new_auth_key_mtx(tg))
		return 1;

	/*if (tg_new_auth_key1(tg))*/
		/*return 1;*/

	/*if (tg_connect(tg))*/
		/*return 1;*/

	//tg_update(tg);

	/*tg_get_dialogs(tg, 10, 0, */
			/*NULL, NULL, */
			/*tg, dialogs_callback);*/

	printf("press any key to exit\n");
	getchar();

	return 0;
}
