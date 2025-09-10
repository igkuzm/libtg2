/**
 * File              : hsh.h
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 10.09.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#ifndef TL_HSH_H
#define TL_HSH_H

#include "../../essential/buf.h"

extern buf_t tg_hsh_sha1(buf_t b);
extern buf_t tg_hsh_sha256(buf_t b);

extern buf_t tg_pbkdf2_sha512(
		buf_t password, buf_t salt, int iteration_count);

extern buf_t tg_hsh_sha1_free(buf_t b);
extern buf_t tg_hsh_sha256_free(buf_t b);

#endif /* defined(TL_HSH_H) */
