#include "deserialize.h"
#include <stdio.h>
#include <string.h>

uint32_t deserialize_ui32(buf_t *b){
	uint32_t c;
	c = buf_get_ui32(*b);
	b->data += 4;
	b->size -= 4;
	//*b = buf_add(b->data + 4, b->size - 4);
	return c;
}

uint64_t deserialize_ui64(buf_t *b){
	uint64_t c;
	c = buf_get_ui64(*b);
	b->data += 8;
	b->size -= 8;
	//*b = buf_add(b->data + 8, b->size - 8);
	return c;
}

double deserialize_double(buf_t *b){
	double c;
	c = buf_get_double(*b);
	b->data += 8;
	b->size -= 8;
	//*b = buf_add(b->data + 8, b->size - 8);
	return c;
}

buf_t deserialize_buf(buf_t *b, int size){
	buf_t ret = buf_add(b->data, size);
	b->data += size;
	b->size -= size;
	//*b = buf_add(b->data + size, b->size - size);
	return ret;
}

buf_t deserialize_bytes(buf_t *b)
{
	/*buf_dump(*b);*/
  buf_t s;
	buf_init(&s);

  buf_t byte = buf_add(b->data, 4);
  int offset = 0;
  uint32_t len = 0;

  if (byte.data[0] <= 253) {
    len = byte.data[0];
		// skip 1 byte
		//*b = buf_add(b->data + 1, b->size - 1);
		b->data += 1;
		b->size -= 1;
		s = buf_add(b->data, len);
		offset = 1;
  } else if (byte.data[0] >= 254) {
    uint8_t start = 0xfe;
    buf_t s1 = buf_add((uint8_t *)&start, 1);
    buf_t s2 = buf_add(b->data, 1);

    if (!buf_cmp(s1, s2)) {
      printf("can't deserialize bytes");
    }

    buf_t len_ = buf_add(b->data + 1, 3);
    len_.size = 4; // hack
    len = buf_get_ui32(len_);
		// skip 4 bytes
		//*b = buf_add(b->data + 4, b->size - 4);
		b->data += 4;
		b->size -= 4;
    s = buf_add(b->data, len);
  } else {
    printf("can't deserialize bytes");
  }
	
	//*b = buf_add(b->data + len, b->size - len);
	b->data += len;
	b->size -= len;
  
	// padding
	int pad = (4 - ((len + offset) % 4)) % 4;
	if (pad) {
		//*b = buf_add(b->data + pad, b->size - pad);
		b->data += pad;
		b->size -= pad;
	}

	/*printf("STRING: %s\n", s.data);*/
  return s;
}