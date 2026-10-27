# SPDX-License-Identifier: GPL-3.0-or-later
# Derived from GCC16 gcc/Makefile.in's libgcc.mvars recipe. The configured
# values are needed by libgcc's original Makefile; its compiler/specs targets
# are not prerequisites for emitting these two configuration variables.
.PHONY: qom-libgcc-mvars
qom-libgcc-mvars: config.status Makefile
	: > tmp-libgcc.mvars
	echo GCC_CFLAGS = '$(GCC_CFLAGS)' >> tmp-libgcc.mvars
	echo INHIBIT_LIBC_CFLAGS = '$(INHIBIT_LIBC_CFLAGS)' >> tmp-libgcc.mvars
	mv tmp-libgcc.mvars libgcc.mvars
