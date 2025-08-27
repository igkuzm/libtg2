#ifndef DESERIALIZE_H
#define DESERIALIZE_H
#include "buf.h"
uint32_t deserialize_ui32(buf_t *b);
uint64_t deserialize_ui64(buf_t *b);
double   deserialize_double(buf_t *b);
buf_t    deserialize_buf(buf_t *b, int size);
buf_t    deserialize_bytes(buf_t *b);
#define deserialize_string(b) deserialize_bytes(b)
#endif /* ifndef DESERIALIZE_H */
