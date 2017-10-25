#ifndef _MM_API_H
#define _MM_API_H
#define IOMEM_CHUNKS 4096
struct iomem {
	__u64 vaddr;
	__u64 iova;
	__u64 size;
};

void *iomem_init(void);
int iomem_free(void *io);
#endif
