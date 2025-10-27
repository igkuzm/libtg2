#include "serialize.h"
#include <string.h>
#include <stdbool.h>

buf_t serialize_bytes(
		uint8_t *bytes, size_t size)
{
	buf_t s;
	uint32_t size_le = htole32(size);
	if (size <= 253){
	  s = buf_new_data((uint8_t *)&size_le, 1);
	  buf_t b = buf_new_data(bytes, size);
      s = buf_cat_buf(s, b);
      int pad = (4 - (s.size % 4)) % 4;
      buf_t p = buf_new();
      p.size = pad;
      s = buf_cat_buf(s, p);
	} else {
	  uint8_t start = 0xfe;
      s = buf_new_data((uint8_t *)&start, 1);
      buf_t len = buf_new_data((uint8_t *)&size_le, 3);
      s = buf_cat_buf(s, len);
      buf_t b = buf_new_data(bytes, size);
      s = buf_cat_buf(s, b);
      int pad = (4 - (s.size % 4)) % 4;

      if (pad) {
        buf_t p = buf_new();
        p.size = pad;
        s = buf_cat_buf(s, p);
      }
	}
	return s;
}

buf_t serialize_string(const char *string)
{
	return serialize_bytes(
			(uint8_t *)string, strlen(string));
}

static bool flag_is_set(int value, int flag)
{
	int flagb = (1 << flag);
	return (value & flagb) != flagb;
}

buf_t serialize_str(buf_t b)
{
  return serialize_bytes(b.data, b.size);
}


