/**
 * File              : hsh.c
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 10.09.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#include "sha1.h"
/*#include "sha256.h"*/
#include "hsh.h"
#include <openssl/sha.h>

buf_t tg_hsh_sha1(buf_t b)
{
  buf_t h = buf_new();
	SHA1(b.data, b.size, h.data);
	/* sha1(b.data, b.size, h.data); */
  h.size = 20;

  return h;
}

buf_t tg_hsh_sha256(buf_t b)
{
  buf_t h = buf_new();
	SHA256(b.data, b.size, h.data);
  /*sha256_bytes(b.data, b.size, h.data);*/
  h.size = 256;

  return h;
}

buf_t tg_hsh_sha1_free(buf_t b){
	buf_t h = tg_hsh_sha1(b);
	buf_free(b);
	return h;
}

buf_t tg_hsh_sha256_free(buf_t b){
	buf_t h = tg_hsh_sha256(b);
	buf_free(b);
	return h;
}
