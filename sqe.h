#ifndef _COMMON_H
#define _COMMON_H

#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/param.h>

#include <Judy.h>

struct socket_info;

struct socket_info
{
	int fd;
	void (*read_handler)(struct socket_info *si);
	void (*write_handler)(struct socket_info *si);
};

const char *thisprogname(void);
void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);
struct socket_info *new_socket_info(int fd);
void delete_socket_info(struct socket_info *si);
void event_loop(void);

#endif
