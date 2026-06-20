#ifndef TAP_H
#define TAP_H
#include <stddef.h>
int tap_open(char *name);
int tap_read(int fd, unsigned char *buf, size_t cap);
int tap_write(int fd, const unsigned char *buf, size_t len);
#endif
