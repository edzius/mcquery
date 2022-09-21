#ifndef _LOGGER_H
#define _LOGGER_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int log_verbose;

static void inline __attribute__((noreturn)) die(const char *format, ... )
{
	if (format != NULL) {
		va_list ap;

		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		fprintf(stderr, ": %s (%i)\n", strerror(errno), errno);
		fflush(stderr);
	}

	exit(1);
}

static int inline hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
	return 0;
}

#define log_dump(data, size) (void)((log_verbose > 0) && hexdump(data, size))
#define log_write(lvl, fmt, ...) fprintf(stdout, "["lvl"] "fmt"\n", ##__VA_ARGS__)
#define log_error(fmt, ...) log_write("E", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_write("W", fmt, ##__VA_ARGS__)
#define log_notice(fmt, ...) log_write("N", fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) (void)((log_verbose > 0) && log_write("I", fmt, ##__VA_ARGS__))
#define log_debug(fmt, ...) (void)((log_verbose > 1) && log_write("D", fmt, ##__VA_ARGS__))

#endif // _LOGGER_H
