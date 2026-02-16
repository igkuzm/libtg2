/**
 * File              : hsh.c
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 16.02.2026
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#include "sha1.h"
#include "sha256.h"
#include "hsh.h"
#include <openssl/sha.h>

buf_t tg_hsh_sha1(buf_t b)
{
	buf_t h1 = buf_new();
	buf_t h2 = buf_new();
	SHA1(b.data, b.size, h1.data);
	sha1(b.data, b.size, h2.data); 
	h1.size = 20;
	h2.size = 20;
	printf("OPENSSL SHA1:\n");
	buf_dump(h1);
	printf("MTX SHA1:\n");
	buf_dump(h2);
	printf("use MTX SHA1\n");
	return h2;
}

buf_t tg_hsh_sha256(buf_t b)
{
  buf_t h = buf_new();
  //SHA256(b.data, b.size, h.data);
  sha256_bytes(b.data, b.size, h.data);
  h.size = 32;

  return h;
}
