#ifndef _COMMON_H
#define _COMMON_H

#define TO_GB(x) (x * 1024ULL * 1024ULL * 1024ULL)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef odp_container_of
#define odp_container_of(pointer, type, member) \
	((type *)(void *)(((char *)pointer) - offsetof(type, member)))
#endif

#endif
