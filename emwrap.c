// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#include <stdlib.h>
#include <stdio.h>

char *secure_getenv(const char *name) {
	return getenv(name);
}
int res_search(const char *dname, int class, int type, unsigned char *answer, int anslen) {
	fprintf(stderr, "DNS SEARCH: %s\n", dname);
	return -1;
}
int initgroups(const char *user, int group) {
	return -1;
}
