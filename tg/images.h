#ifndef TG_IMAGES_H
#define TG_IMAGES_H
#include "../libtg.h"

extern buf_t image_from_photo_stripped(buf_t bytes);
extern char *image_from_svg_path(buf_t encoded);

#endif /* ifndef TG_IMAGES_H */
