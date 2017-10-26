#include <odp_posix_extensions.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <mm_api.h>
#include <common.h>

/**
 * Reserve a 4GB contiguous address space and position it,
 * no pages are actually allocated and mapped into this address space
 * it is just making sure that overtime, we'll have 4GB
 */
void *iomem_init(void)
{
	void *tmp;
	tmp = mmap(NULL, TO_GB(4), PROT_READ | PROT_WRITE, MAP_SHARED |
		   MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (tmp == MAP_FAILED) {
		printf("Could not reserve a contiguous address space\n");
		return NULL;
	}

	return tmp;
}

int iomem_free(void *iobase)
{
	return munmap(iobase, TO_GB(4));
}
