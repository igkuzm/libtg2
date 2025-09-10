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
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <assert.h>
#include <stdio.h>

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

buf_t tg_pbkdf2_sha512(
		buf_t password, buf_t salt, int iteration_count)
{
	assert(iteration_count > 0);
	buf_t dest = buf_new();

	const EVP_MD *evp_md = EVP_sha512();
  int hash_size = EVP_MD_size(evp_md);
	
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  unsigned char counter[4] = {0, 0, 0, 1};
  HMAC_Init_ex(&ctx, password.data, password.size, evp_md, NULL);
  HMAC_Update(&ctx, salt.data, salt.size);
  HMAC_Update(&ctx, counter, 4);
  HMAC_Final(&ctx, dest.data, NULL);
  HMAC_CTX_cleanup(&ctx);

	unsigned char buf[64];
	std::copy(dest.ubegin(), dest.uend(), buf);
	for (int iter = 1; iter < iteration_count; iter++) {
		if (HMAC(evp_md, password.data, password.size,
				 	buf, hash_size, buf, NULL) == NULL) 
		{
			perror("Failed to HMAC");
			return dest; 
		}
		int i;
		for (i = 0; i < hash_size; i++) {
			dest[i] = dest[i] ^ buf[i];
		}
	}
#else
  if (PKCS5_PBKDF2_HMAC(
			(char *)password.data, password.size, 
			salt.data, salt.size, 
			iteration_count, evp_md, 
			hash_size, dest.data) != 1)
	{
		perror("Failed to HMAC");
		return dest; 
	}
#endif
	
	dest.size = hash_size;
	return dest; 
}
