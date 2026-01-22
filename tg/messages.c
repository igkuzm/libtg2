#include "tg.h"
#include "database/database.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void tg_get_messages(tg_t *tg, 
		int nids, uint32_t *ids,
		void *userdata, 
		void (*callback)(void *userdata, tl_t **messages))
{
	int i, nmessages = 0;
	tl_t **messages; 
	char sql[BUFSIZ];
	
	ON_LOG(tg, "%s", __func__);

	assert(nids > 0);
	assert(ids);

	strcat(sql, "SELECT data FROM messages WHERE ");	
	for (i = 0; i < nmessages;) {
		char str[32];
		sprintf(str, "id == %d ", ids[i++]);
		strcat(sql, str);	
		if (i < nmessages)
			strcat(sql, "OR ");	
	}
	strcat(sql, "ORDER BY message_date ASC;");	
			
	messages = MALLOC(sizeof(tl_t*) * nids, return);

	tg_sqlite3_for_each(tg, sql, stmt)
	{
		int size = sqlite3_column_bytes(stmt, 0);
		const void *data = sqlite3_column_blob(stmt, 0);
		buf_t buf = buf_new_data((uint8_t *)data, size);
		tl_t *tl = tl_deserialize(&buf);
		buf_free(buf);
		messages[nmessages++] = tl;
	}
	messages[nmessages] = NULL;

	if (callback)
		callback(userdata, messages);

	// cleenup
	for (i = 0; i < nmessages; ++i)
		tl_free(messages[i]);
	free(messages);
}


