#include <stdio.h>
#include <stdint.h>

#include "pktio/mdev.h"

static char to_printable(uint8_t val)
{
	if (val >= ' ' && val <= '~')
		return val;
	else
		return '.';
}

void odp_hexdump(const uint8_t *data, size_t size)
{
	char ascii[17];
	size_t i, j;

	printf("0000  ");

	ascii[16] = '\0';

	for (i = 0; i < size; ++i) {
		printf("%02X ", data[i]);
		ascii[i % 16] = to_printable(data[i]);
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s\n", ascii);
				if (i + 1 < size)
					printf("%04lx  ", i + 1);
			} else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8)
					printf(" ");
				for (j = (i + 1) % 16; j < 16; ++j)
					printf("   ");
				printf("|  %s\n", ascii);
			}
		}
	}
}
