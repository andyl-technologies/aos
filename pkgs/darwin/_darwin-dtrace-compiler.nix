##! Linux-native Apple DTrace provider-header and DOF compiler.
{
  mkDerivation,
  fetchurl,
  llvm,
  gcc,
  glibc,
  zlib,
}: let
  dtraceRevision = "fd2a404c772e8ce1d29f210032e9831fa845f688";
  cctoolsRevision = "d9456c221e1f462e17c0b3297748bc089d5a861e";
  xnuRevision = "fa29287aa2f0115271e091f1031f53c9e024005d";

  dtraceSource = fetchurl {
    urls = ["https://github.com/darlinghq/darling-dtrace/archive/${dtraceRevision}.tar.gz"];
    hash = "sha256-dKDTXaub0SF7Fzn7EUJ1RIBiHjro4/22q1tOBEN2jiQ=";
  };
  cctoolsSource = fetchurl {
    urls = ["https://github.com/tpoechtrager/cctools-port/archive/${cctoolsRevision}.tar.gz"];
    hash = "sha256-lvC4VjddJMVyNszhOjHFvy+kiEPhHsnCNR4zLuRCe/Q=";
  };
  xnuSource = fetchurl {
    urls = ["https://github.com/darlinghq/darling-xnu/archive/${xnuRevision}.tar.gz"];
    hash = "sha256-7YKobVQNnsCI2kjGInfP72P/u1UrXBdEWAT/5UEmvac=";
  };
in
  mkDerivation {
    pname = "darwin-dtrace-compiler";
    version = "370.40.1-${builtins.substring 0 8 dtraceRevision}";

    src = dtraceSource;
    buildDeps = [llvm zlib];
    runtimeDeps = [zlib];
    hardeningDisable = ["all"];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          mv darling-dtrace-${dtraceRevision} source
          cd source

          mkdir cctools-source xnu-source
          tar xf ${cctoolsSource} --strip-components=1 -C cctools-source
          tar xf ${xnuSource} --strip-components=1 -C xnu-source
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./darling-dtrace-nodev.patch}
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p compat-native/sys compat-native/machine compat-native/architecture
          cp xnu-source/bsd/sys/dtrace.h compat-native/sys/dtrace.h
          cp xnu-source/bsd/sys/dtrace_glue.h compat-native/sys/dtrace_glue.h
          cp xnu-source/bsd/sys/fasttrap.h compat-native/sys/fasttrap.h
          cp xnu-source/bsd/sys/fasttrap_isa.h compat-native/sys/fasttrap_isa.h
          cp xnu-source/bsd/i386/fasttrap_isa.h compat-native/machine/fasttrap_isa.h
          cp -R cctools-source/cctools/include/foreign/mach compat-native/
          cp -R cctools-source/cctools/include/foreign/i386 compat-native/
          cp -R cctools-source/cctools/include/foreign/architecture compat-native/
          cp -R cctools-source/cctools/include/foreign/libkern compat-native/

          # The byte-order header's Darwin libc dependencies are irrelevant to
          # NODEV compilation. libelf uses the explicit swap hook below.
          printf '%s\n' '#pragma once' > compat-native/architecture/byte_order.h
          printf '%s\n' \
            '#pragma once' \
            '#define TARGET_OS_OSX 1' \
            '#define TARGET_OS_MAC 1' \
            '#define TARGET_OS_EMBEDDED 0' \
            '#define TARGET_OS_IPHONE 0' \
            '#define TARGET_OS_SIMULATOR 0' \
            '#define TARGET_OS_IOS 0' \
            > compat-native/TargetConditionals.h

          common_flags="--gcc-toolchain=${gcc} -B${glibc}/lib -idirafter ${glibc.dev}/include -D__APPLE__ -D__linux__ -D__LITTLE_ENDIAN__ -DCPU_TYPE_ARM64=0x0100000c -Duser_addr_t=uint64_t -D_INT64_TYPE -D_LONGLONG_TYPE -D_ILP32 -DCTF_OLD_VERSIONS -DNS_BLOCK_ASSERTIONS -DNDEBUG -DPRIVATE -include string.h -fPIC -ffunction-sections -fdata-sections -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types"
          include_flags="-I${zlib}/include -Icompat-native -Icctools-source/cctools/include -I. -Icompat/opensolaris -Icompat/opensolaris/sys -Igen/libdtrace -Ilib/libctf/common -Ilib/libelf -Ilib/libdtrace/i386 -Ilib/libdtrace/arm -Ilib/libdwarf -Ilib/libdwarf/cmplrs -Ilib/libdtrace/common -Ilib/libproc"

          ctf_sources="
            lib/libctf/common/ctf_create.c lib/libctf/common/ctf_decl.c
            lib/libctf/common/ctf_error.c lib/libctf/common/ctf_hash.c
            lib/libctf/common/ctf_labels.c lib/libctf/common/ctf_lib.c
            lib/libctf/common/ctf_lookup.c lib/libctf/common/ctf_open.c
            lib/libctf/common/ctf_subr.c lib/libctf/common/ctf_types.c
            lib/libctf/common/ctf_util.c"
          elf_sources="
            lib/libelf/clscook_ELF64.c lib/libelf/clscook.c lib/libelf/cntl.c
            lib/libelf/cook.c lib/libelf/data.c lib/libelf/gelf.c
            lib/libelf/getehdr.c lib/libelf/getident.c lib/libelf/getscn.c
            lib/libelf/getshdr.c lib/libelf/input.c lib/libelf/kind.c
            lib/libelf/ndxscn.c lib/libelf/nextscn.c lib/libelf/strptr.c
            lib/libelf/xlate.c lib/libelf/begin.c lib/libelf/end.c
            lib/libelf/error.c lib/libelf/getdata.c lib/libelf/getshstrndx.c
            lib/libelf/xlate64.c"
          dwarf_sources="
            lib/libdwarf/dwarf_abbrev.c lib/libdwarf/dwarf_addr_finder.c
            lib/libdwarf/dwarf_alloc.c lib/libdwarf/dwarf_arange.c
            lib/libdwarf/dwarf_die_deliv.c lib/libdwarf/dwarf_error.c
            lib/libdwarf/dwarf_form.c lib/libdwarf/dwarf_frame.c
            lib/libdwarf/dwarf_frame2.c lib/libdwarf/dwarf_frame3.c
            lib/libdwarf/dwarf_funcs.c lib/libdwarf/dwarf_global.c
            lib/libdwarf/dwarf_init_finish.c lib/libdwarf/dwarf_leb.c
            lib/libdwarf/dwarf_line.c lib/libdwarf/dwarf_line2.c
            lib/libdwarf/dwarf_loc.c lib/libdwarf/dwarf_macro.c
            lib/libdwarf/dwarf_print_lines.c lib/libdwarf/dwarf_pubtypes.c
            lib/libdwarf/dwarf_query.c lib/libdwarf/dwarf_sort_line.c
            lib/libdwarf/dwarf_string.c lib/libdwarf/dwarf_types.c
            lib/libdwarf/dwarf_util.c lib/libdwarf/dwarf_vars.c
            lib/libdwarf/dwarf_weaks.c"
          dtrace_sources="
            lib/libdtrace/common/dt_aggregate.c lib/libdtrace/common/dt_as.c
            lib/libdtrace/common/dt_buf.c lib/libdtrace/common/dt_cc.c
            lib/libdtrace/common/dt_cg.c lib/libdtrace/common/dt_consume.c
            lib/libdtrace/common/dt_decl.c lib/libdtrace/common/dt_dis.c
            lib/libdtrace/common/dt_dof.c lib/libdtrace/common/dt_error.c
            lib/libdtrace/common/dt_errtags.c lib/libdtrace/common/dt_handle.c
            lib/libdtrace/common/dt_ident.c lib/libdtrace/common/dt_inttab.c
            lib/libdtrace/common/dt_list.c lib/libdtrace/common/dt_map.c
            lib/libdtrace/common/dt_module.c lib/libdtrace/common/dt_names.c
            lib/libdtrace/common/dt_open.c lib/libdtrace/common/dt_options.c
            lib/libdtrace/common/dt_parser.c lib/libdtrace/common/dt_pcb.c
            lib/libdtrace/common/dt_pid.c lib/libdtrace/common/dt_pq.c
            lib/libdtrace/common/dt_pragma.c lib/libdtrace/common/dt_print.c
            lib/libdtrace/common/dt_printf.c lib/libdtrace/common/dt_program.c
            lib/libdtrace/common/dt_provider.c lib/libdtrace/common/dt_regset.c
            lib/libdtrace/common/dt_string.c lib/libdtrace/common/dt_strtab.c
            lib/libdtrace/common/dt_subr.c lib/libdtrace/common/dt_sugar.c
            lib/libdtrace/common/dt_work.c lib/libdtrace/common/dt_xlator.c
            lib/libdtrace/apple/dt_pid_apple.c
            lib/libdtrace/apple/dt_provider_apple.c
            lib/libdtrace/apple/dt_subr_apple.c
            lib/libdtrace/arm/dt_isadep.c lib/libdtrace/i386/dt_isadep.c
            lib/libdtrace/i386/dis_tables.c compat/opensolaris/darwin_shim.c
            gen/libdtrace/lex.yy.c gen/libdtrace/y.tab.c"

          mkdir -p objects
          for source_file in $ctf_sources $elf_sources $dwarf_sources $dtrace_sources; do
            object_file="objects/$source_file.o"
            mkdir -p "$(dirname "$object_file")"
            ${llvm}/bin/clang $common_flags -Dyydebug= $include_flags \
              -c "$source_file" -o "$object_file"
          done

          mkdir -p objects/lib/libdtrace/apple objects/cmd/usdtheadergen objects/aos
          ${llvm}/bin/clang++ $common_flags $include_flags \
            -c lib/libdtrace/apple/dt_ld.cpp \
            -o objects/lib/libdtrace/apple/dt_ld.cpp.o
          ${llvm}/bin/clang $common_flags -Dyydebug= $include_flags \
            -c cmd/usdtheadergen/usdtheadergen.c \
            -o objects/cmd/usdtheadergen/usdtheadergen.c.o
          ${llvm}/bin/clang $common_flags -Dyydebug= $include_flags \
            -c ${./darling-dtrace-nodev-stubs.c} \
            -o objects/aos/darling-dtrace-nodev-stubs.c.o

          mkdir -p "$out/bin" "$out/lib"
          object_files="$(find objects/lib objects/compat objects/gen -name '*.o' -print) objects/aos/darling-dtrace-nodev-stubs.c.o"
          ar crs "$out/lib/libdtrace_dof.a" $object_files
          c++ -Wl,--gc-sections \
            objects/cmd/usdtheadergen/usdtheadergen.c.o \
            "$out/lib/libdtrace_dof.a" -lz \
            -o "$out/bin/dtrace"

          printf '%s\n' 'provider aos { probe build(uint64_t); };' > provider.d
          "$out/bin/dtrace" -h -s provider.d -o provider.h
          grep -q 'AOS_BUILD' provider.h
        '';
      }
    ];

    meta = {
      description = "Linux-native Apple DTrace header and DOF compiler";
      license = "APSL-2.0 AND CDDL-1.0 AND LGPL-2.1-only";
    };
  }
