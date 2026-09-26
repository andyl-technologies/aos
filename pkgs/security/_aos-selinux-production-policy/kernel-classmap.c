/* SPDX-License-Identifier: GPL-2.0-only */
/* Emits the ordered SELinux class map compiled from the pinned kernel source. */
#include <stddef.h>
#include <stdio.h>

struct security_class_mapping {
	const char *name;
	const char *perms[sizeof(unsigned int) * 8 + 1];
};

#include "classmap.h"

int main(void)
{
	const struct security_class_mapping *mapping;

	for (mapping = secclass_map; mapping->name != NULL; mapping++) {
		size_t permission_index;

		if (fputs(mapping->name, stdout) == EOF)
			return 1;

		for (permission_index = 0;
		     mapping->perms[permission_index] != NULL;
		     permission_index++) {
			if (printf("\t%s", mapping->perms[permission_index]) < 0)
				return 1;
		}

		if (putchar('\n') == EOF)
			return 1;
	}

	return 0;
}
