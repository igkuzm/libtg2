/*
 *  strndup.c
 *  ProZubi
 *
 *  Created by Igor Sementsov on 19.08.25.
 *  Copyright 2025 ProZubi. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>

char *strndup(const char *str, size_t chars){
	size_t n;
	char *buf = (char *)malloc(chars+1);
	if (buf){
		for (n=0; ((n < chars) && (str[n] != 0)); n++) {
			buf[n] = str[n];
		}
		buf[n] = 0;
	}
	return buf;
}