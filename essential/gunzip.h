#ifndef GUNZIP_H
#define GUNZIP_H

#include "buf.h"
int gunzip_buf(buf_t *dst, buf_t src);
char *gunzip_buf_err(int err); // handle errors

#endif