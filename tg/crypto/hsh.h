/**
 * File              : hsh.h
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 21.11.2024
 * Last Modified Date: 11.09.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */
#ifndef TG_HSH_H
#define TG_HSH_H

#include "../../essential/buf.h"

extern buf_t tg_hsh_sha1(buf_t b);
extern buf_t tg_hsh_sha256(buf_t b);

#endif /* defined(TG_HSH_H) */
