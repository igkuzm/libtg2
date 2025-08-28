#ifndef TG_PROGRESS_H
#define TG_PROGRESS_H
/* function to handle download/upload progress 
 * %ptr - pointer to data for progress function
 * %dltotal - total downloaded size
 * %dlnow - current downloaded size
 * %ultotal - total uploaded size
 * %ulnow - current uploaded size */
typedef int 
tg_progress_fun(void *ptr, 
		double dltotal, double dlnow, 
		double ultotal, double ulnow); 

#endif /* ifndef TG_PROGRESS_H */
