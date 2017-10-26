#ifndef _MM_API_H
#define _MM_API_H

#include <stdint.h>

#define IOMEM_CHUNKS 4096

struct iomem {
	uint8_t *vaddr;
	__u64 iova;
	__u64 size;
};

void *iomem_init(void);
int iomem_free(void *io);
#endif
