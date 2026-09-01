/* Linux-hosted, compiler-only hooks for Darling's Apple DTrace frontend. */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint32_t
OSSwapBigToHostInt32(uint32_t value)
{
	return __builtin_bswap32(value);
}

char *
fgetln(FILE *stream, size_t *length)
{
	static char *line;
	static size_t capacity;
	ssize_t result = getline(&line, &capacity, stream);

	if (result < 0)
		return NULL;

	*length = (size_t)result;
	return line;
}

void
dt_proc_init(void *handle)
{
	(void)handle;
}

void
dt_proc_fini(void *handle)
{
	(void)handle;
}

void
dtrace_update_kernel_symbols(void *handle)
{
	(void)handle;
}

/* Runtime tracing and process inspection are unavailable in NODEV mode. */
__attribute__((noreturn)) static void
nodev_only(void)
{
	abort();
}

#define NODEV(name) \
	void *name(void) \
	{ \
		nodev_only(); \
	}

NODEV(dt_module_sym_location)
NODEV(dtrace_kernel_path)
NODEV(Plmid_to_map)
NODEV(Pobjname)
NODEV(Plmid)
NODEV(Pstatus)
NODEV(Ppltdest)
NODEV(Plookup_by_addr)
NODEV(Pname_to_map)
NODEV(dt_proc_grab)
NODEV(dt_proc_lookup)
NODEV(dt_proc_release)
NODEV(Pxlookup_by_name)
NODEV(Pobject_iter)
NODEV(Pobjc_method_iter)
NODEV(Psymbol_iter_by_addr)
NODEV(Pxlookup_by_name_new_syms)
NODEV(Pobject_iter_new_syms)
NODEV(Pobjc_method_iter_new_syms)
NODEV(Psymbol_iter_by_addr_new_syms)
NODEV(dt_module_get_types)
NODEV(dtrace_lookup_by_addr)
NODEV(dt_proc_lock)
NODEV(dt_proc_unlock)
NODEV(Paddr_to_map)
NODEV(dt_proc_bpdisable)
NODEV(dt_proc_bpenable)
NODEV(Pread)
