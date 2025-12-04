/**
 * File              : endian.h
 * Author            : Igor V. Sementsov <ig.kuzm@gmail.com>
 * Date              : 20.02.2023
 * Last Modified Date: 04.12.2025
 * Last Modified By  : Igor V. Sementsov <ig.kuzm@gmail.com>
 */

#ifndef _ENDIAN_H
#define _ENDIAN_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <byteswap.h>

static bool is_little_endian()
{
	int x = 1;
	return *(char*)&x;
}

static uint16_t htole16 (uint16_t x)
{
	if (!is_little_endian())
		return bswap_16(x);
	return x;
}

static uint32_t htole32 (uint32_t x)
{
	if (!is_little_endian())
		return bswap_32(x);
	return x;
}

static uint64_t htole64 (uint64_t x)
{
	if (!is_little_endian())
		return bswap_64(x);
	return x;
}

// cfb to host
static uint16_t le16toh (uint16_t x)
{
	if (!is_little_endian())
		return bswap_16(x);
	return x;
}

static uint32_t le32toh (uint32_t x)
{
	if (!is_little_endian())
		return bswap_32(x);
	return x;
}

static uint64_t le64toh (uint64_t x)
{
	if (!is_little_endian())
		return bswap_64(x);
	return x;
}

static uint16_t htobe16 (uint16_t x)
{
	if (is_little_endian())
		return bswap_16(x);
	return x;
}

static uint32_t htobe32 (uint32_t x)
{
	if (is_little_endian())
		return bswap_32(x);
	return x;
}

static uint64_t htobe64 (uint64_t x)
{
	if (is_little_endian())
		return bswap_64(x);
	return x;
}

// cfb to host
static uint16_t be16toh (uint16_t x)
{
	if (is_little_endian())
		return bswap_16(x);
	return x;
}

static uint32_t be32toh (uint32_t x)
{
	if (is_little_endian())
		return bswap_32(x);
	return x;
}

static uint64_t be64toh (uint64_t x)
{
	if (is_little_endian())
		return bswap_64(x);
	return x;
}


#ifdef __cplusplus
}
#endif

#endif //_ENDIAN_H

// vim:ft=c	
