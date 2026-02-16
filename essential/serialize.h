#ifndef SERIALIZE_H
#define SERIALIZE_H
#include "buf.h"
buf_t serialize_bytes(uint8_t *bytes, uint32_t size);
buf_t serialize_string(const char *string);
buf_t serialize_str(buf_t b);
#endif /* ifndef SERIALIZE_H */
