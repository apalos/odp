#ifndef _COMMON_H
#define _COMMON_H

#define TO_GB(x) (x * 1024ULL * 1024ULL * 1024ULL)

#define barrier() __asm__ __volatile__("": : :"memory")
#define dma_wmb() barrier()
#define dma_rmb() barrier()

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#ifndef odp_container_of
#define odp_container_of(pointer, type, member) \
	((type *)(void *)(((char *)pointer) - offsetof(type, member)))
#endif

/* FIXME: make sure __builtin_constant_p(divisor) && (divisor == 2^n) */
#define DIV_ROUND_UP(x, divisor) \
	(((x) + (divisor) - 1) >> __builtin_ctz(divisor))

void odp_hexdump(const uint8_t *data, size_t size);

#endif