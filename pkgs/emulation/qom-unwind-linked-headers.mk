# Copied GNU GCC 16.2 libgcc rules with their original license retained.
# Only the recorded x86_64 link/header targets are requested by the caller.
unwind_header = unwind-generic.h
md_unwind_def_header = no-unwind.h
md_unwind_header = i386/linux-unwind.h
thread_header = gthr-posix.h
libgcc_tm_defines =
libgcc_tm_file = $(srcdir)/config/i386/elf-lib.h $(srcdir)/config/i386/value-unwind.h

unwind.h: $(srcdir)/$(unwind_header)
	-$(LN_S) $< $@
md-unwind-def.h: $(srcdir)/config/$(md_unwind_def_header)
	-$(LN_S) $< $@
md-unwind-support.h: $(srcdir)/config/$(md_unwind_header)
	-$(LN_S) $< $@
sfp-machine.h: $(srcdir)/config/$(sfp_machine_header)
	-$(LN_S) $< $@
gthr-default.h: $(srcdir)/$(thread_header)
	-$(LN_S) $< $@

libgcc_tm.h: libgcc_tm.stamp; @true
libgcc_tm.stamp:
	DEFINES='$(libgcc_tm_defines)' HEADERS='$(libgcc_tm_file)' \
		$(srcdir)/mkheader.sh > tmp-libgcc_tm.h
	$(SHELL) $(srcdir)/../move-if-change tmp-libgcc_tm.h libgcc_tm.h
	echo timestamp > $@

