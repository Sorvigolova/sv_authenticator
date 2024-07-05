#ifndef __COMMON_H__
#define __COMMON_H__

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>


#define PACKET_BUFFER_SIZE 0x10000

void dump_data(const void* data, uint64_t size);

static inline uint32_t align_up(uint32_t x, uint32_t alignment) {
	return (x + (alignment - 1)) & ~(alignment - 1);
}


uint8_t packet_buffer[PACKET_BUFFER_SIZE];

#endif
