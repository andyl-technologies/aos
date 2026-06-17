# stdenv/cc-wrapper.nix — Compiler and linker wrapper script generator
#
# Creates wrapper scripts for gcc, g++, and ld that inject correct
# -isystem, -L, -rpath, and -dynamic-linker flags, and translate the
# AOS_HARDENING_ENABLE token list (set per package by lib/derivations.nix)
# into concrete compiler/linker hardening flags.
#
# The token vocabulary and set algebra live in lib/hardening.nix. This file
# owns the token → flag mapping. `defaultHardening` is the space-separated
# default token list baked in as a fallback for environments that don't set
# AOS_HARDENING_ENABLE (interactive shells, ad-hoc compiler use); inside an
# AOS build the variable is always present, so an empty value (from
# hardeningDisable = [ "all" ]) genuinely disables everything.
#
{
  cc,
  libc,
  binutils_,
  shell,
  coreutils,
  hostPlatform,
  storeDir ? "/nix/store",
  defaultHardening ? "",
  staticDefault ? false,
  staticNoPie ? false,
}: let
  system = hostPlatform.system;
  targetTriple = hostPlatform.config;
  dynamicLinker = "${libc}/lib/${hostPlatform.dynamicLinker}";
  libcDev = libc.dev or libc;
  libcStatic = libc.static or libc;

  mkdir = "${coreutils}/bin/mkdir";
  cat = "${coreutils}/bin/cat";
  chmod = "${coreutils}/bin/chmod";
  ln = "${coreutils}/bin/ln";
  echo = "${coreutils}/bin/echo";

  compilerRuntimeLdFlags =
    if staticDefault
    then "if [ \"$exec_link\" = true ]; then\n    extra_ldflags=\"$extra_ldflags -static${
      if staticNoPie
      then " -no-pie"
      else ""
    }\"\n  fi"
    else "extra_ldflags=\"$extra_ldflags -Wl,-rpath,${libc}/lib\"\n  extra_ldflags=\"$extra_ldflags -Wl,--dynamic-linker=${dynamicLinker}\"\n  extra_ldflags=\"$extra_ldflags -Wl,-rpath-link,${libc}/lib\"";

  directLdRuntimeFlags =
    if staticDefault
    then "extra_flags=\"$extra_flags -L${libcStatic}/lib\"\nextra_flags=\"$extra_flags -static\""
    else "extra_flags=\"$extra_flags -rpath ${libc}/lib\"\nextra_flags=\"$extra_flags --dynamic-linker ${dynamicLinker}\"\nextra_flags=\"$extra_flags -rpath-link ${libc}/lib\"";

  ccLdFlags =
    if staticDefault
    then "-L${libc}/lib -L${libcStatic}/lib -B${libc}/lib -static${
      if staticNoPie
      then " -no-pie"
      else ""
    }"
    else "-L${libc}/lib -L${libcStatic}/lib -Wl,-rpath,${libc}/lib";

  # Shared shell prologue that turns the AOS_HARDENING_ENABLE token list into
  # the flag fragments used by the gcc/g++ wrappers:
  #   $hardening_cflags  — emitted before the package's arguments
  #   $hardening_post    — emitted after the package's arguments (Fortify)
  #   $hardening_ldflags — emitted on the link line
  # `isCxx` adds the C++-only libstdc++ assertions token.
  compilerHardening = isCxx:
    if staticDefault
    then ''
      tokens="''${AOS_HARDENING_ENABLE-${defaultHardening}}"

      has() {
        case " $tokens " in
          *" $1 "*) return 0 ;;
          *) return 1 ;;
        esac
      }

      hardening_cflags=""
      hardening_post=""
      hardening_ldflags=""

      # Early static toolchain tiers predate -fno-PIE/-no-pie. With an empty
      # token set, do not add modern opt-out flags; only honor explicit
      # hardening opt-ins that the caller knows this compiler accepts.
      if has stackprotector; then
        hardening_cflags="$hardening_cflags -fstack-protector-strong --param ssp-buffer-size=4"
      fi

      if has stackclashprotection; then
        hardening_cflags="$hardening_cflags -fstack-clash-protection"
      fi
      if has format; then
        hardening_cflags="$hardening_cflags -Wformat -Wformat-security -Werror=format-security"
      fi
      if has strictflexarrays1; then
        hardening_cflags="$hardening_cflags -fstrict-flex-arrays=1"
      fi
      if has strictflexarrays3; then
        hardening_cflags="$hardening_cflags -fstrict-flex-arrays=3"
      fi
      if has shadowstack; then
        hardening_cflags="$hardening_cflags -fcf-protection=return"
      fi
      if has pacret; then
        hardening_cflags="$hardening_cflags -mbranch-protection=pac-ret"
      fi
      if has trivialautovarinit; then
        hardening_cflags="$hardening_cflags -ftrivial-auto-var-init=zero"
      fi
      if has zerocallusedregs; then
        hardening_cflags="$hardening_cflags -fzero-call-used-regs=used-gpr"
      fi
      ${
        if isCxx
        then ''
          if has glibcxxassertions; then
            hardening_cflags="$hardening_cflags -D_GLIBCXX_ASSERTIONS"
          fi
        ''
        else ""
      }

      # Fortify: force -O2 and clear any inherited level before the package's
      # arguments, then set the requested level after them. This avoids macro
      # redefinition warnings and lets a package's own -O0/-Og make Fortify
      # inert. fortify3 wins over fortify.
      if has fortify3; then
        hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
        hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
      elif has fortify; then
        hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
        hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
      fi

      if [ "$linking" = true ]; then
        if has relro; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,relro"
        fi
        if has bindnow; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,now"
        fi
        if has noexecstack; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,noexecstack"
        fi
      fi
    ''
    else ''
      tokens="''${AOS_HARDENING_ENABLE-${defaultHardening}}"

      has() {
        case " $tokens " in
          *" $1 "*) return 0 ;;
          *) return 1 ;;
        esac
      }

      hardening_cflags=""
      hardening_post=""
      hardening_ldflags=""

      # Stack protector and PIE are GCC build-time defaults, so opting out has
      # to inject negative flags — omitting a positive flag is not enough.
      if has stackprotector; then
        hardening_cflags="$hardening_cflags -fstack-protector-strong --param ssp-buffer-size=4"
      else
        hardening_cflags="$hardening_cflags -fno-stack-protector"
      fi

      if has pie; then
        :
      else
        hardening_cflags="$hardening_cflags -fno-PIE"
      fi

      if has stackclashprotection; then
        hardening_cflags="$hardening_cflags -fstack-clash-protection"
      fi
      if has format; then
        hardening_cflags="$hardening_cflags -Wformat -Wformat-security -Werror=format-security"
      fi
      if has strictflexarrays1; then
        hardening_cflags="$hardening_cflags -fstrict-flex-arrays=1"
      fi
      if has strictflexarrays3; then
        hardening_cflags="$hardening_cflags -fstrict-flex-arrays=3"
      fi
      if has shadowstack; then
        hardening_cflags="$hardening_cflags -fcf-protection=return"
      fi
      if has pacret; then
        hardening_cflags="$hardening_cflags -mbranch-protection=pac-ret"
      fi
      if has trivialautovarinit; then
        hardening_cflags="$hardening_cflags -ftrivial-auto-var-init=zero"
      fi
      if has zerocallusedregs; then
        hardening_cflags="$hardening_cflags -fzero-call-used-regs=used-gpr"
      fi
      ${
        if isCxx
        then ''
          if has glibcxxassertions; then
            hardening_cflags="$hardening_cflags -D_GLIBCXX_ASSERTIONS"
          fi
        ''
        else ""
      }

      # Fortify: force -O2 and clear any inherited level before the package's
      # arguments, then set the requested level after them. This avoids macro
      # redefinition warnings and lets a package's own -O0/-Og make Fortify
      # inert. fortify3 wins over fortify.
      if has fortify3; then
        hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
        hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
      elif has fortify; then
        hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
        hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
      fi

      if [ "$linking" = true ]; then
        if has relro; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,relro"
        fi
        if has bindnow; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,now"
        fi
        if has noexecstack; then
          hardening_ldflags="$hardening_ldflags -Wl,-z,noexecstack"
        fi
        # Active PIE opt-out, executable links only. Shared, relocatable and
        # freestanding links manage their own position-independence.
        if ! has pie && [ "$exec_link" = true ]; then
          hardening_ldflags="$hardening_ldflags -no-pie"
        fi
      fi
    '';

  wrapperDrv = builtins.derivation {
    name = "aos-cc-wrapper";
    inherit system;
    builder = shell;
    args = [
      "-c"
      ''
        set -eu

        ${mkdir} -p $out/bin
        ${mkdir} -p $out/nix-support

        # ── gcc wrapper ──────────────────────────────────────────────
        ${cat} > $out/bin/gcc << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true
        exec_link=true

        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
            -shared|-r|--relocatable|-nostdlib|-nostartfiles|-ffreestanding) exec_link=false ;;
          esac
        done

        # Use -idirafter, not -isystem, for the glibc include dir. -isystem
        # prepends to the system search path, which places glibc's stdlib.h
        # BEFORE the C++ stdlib dir. GCC dedups include paths, so a later
        # -idirafter for the same dir (baked into gcc-stage2's specs) gets
        # dropped as redundant — leaving stdlib.h only at the prepended
        # position, where <cstdlib>'s #include_next <stdlib.h> can't reach
        # it (include_next searches dirs AFTER the one the current header
        # was found in). Result: C++ builds fail with "stdlib.h: No such
        # file". See gcc-stage2.nix + patchelf.nix for the same hazard.
        extra_cflags="$extra_cflags -idirafter ${libcDev}/include"

        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -L${libcStatic}/lib"
          ${compilerRuntimeLdFlags}
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        ${compilerHardening false}

        nix_ldflags=""
        if [ "$linking" = true ] && [ -n "''${NIX_LDFLAGS:-}" ]; then
          nix_ldflags="$NIX_LDFLAGS"
        fi

        exec ${cc}/bin/gcc $extra_cflags $hardening_cflags "$@" $hardening_post $extra_ldflags $hardening_ldflags $nix_ldflags
        WRAPPER_EOF
        ${chmod} +x $out/bin/gcc

        # ── g++ wrapper ──────────────────────────────────────────────
        ${cat} > $out/bin/g++ << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true
        exec_link=true

        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
            -shared|-r|--relocatable|-nostdlib|-nostartfiles|-ffreestanding) exec_link=false ;;
          esac
        done

        # See the gcc wrapper above for why -idirafter instead of -isystem.
        extra_cflags="$extra_cflags -idirafter ${libcDev}/include"

        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -L${libcStatic}/lib"
          ${compilerRuntimeLdFlags}
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        ${compilerHardening true}

        nix_ldflags=""
        if [ "$linking" = true ] && [ -n "''${NIX_LDFLAGS:-}" ]; then
          nix_ldflags="$NIX_LDFLAGS"
        fi

        exec ${cc}/bin/g++ $extra_cflags $hardening_cflags "$@" $hardening_post $extra_ldflags $hardening_ldflags $nix_ldflags
        WRAPPER_EOF
        ${chmod} +x $out/bin/g++

        # ── cc/c++ symlinks ──────────────────────────────────────────
        ${ln} -s gcc $out/bin/cc
        ${ln} -s g++ $out/bin/c++

        # ── ld wrapper ───────────────────────────────────────────────
        ${cat} > $out/bin/ld << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        tokens="''${AOS_HARDENING_ENABLE-${defaultHardening}}"

        has() {
          case " $tokens " in
            *" $1 "*) return 0 ;;
            *) return 1 ;;
          esac
        }

        extra_flags=""
        extra_flags="$extra_flags -L${libc}/lib"
        ${directLdRuntimeFlags}
        # Phase 3: no -L/-rpath for ${cc}/lib{,64} — see gcc wrapper.

        # Token-gated link hardening for direct ld users. The gcc/g++
        # wrappers inject the -Wl, equivalents for driver-based links.
        if has relro; then extra_flags="$extra_flags -z relro"; fi
        if has bindnow; then extra_flags="$extra_flags -z now"; fi
        if has noexecstack; then extra_flags="$extra_flags -z noexecstack"; fi

        exec ${binutils_}/bin/ld $extra_flags "$@"
        WRAPPER_EOF
        ${chmod} +x $out/bin/ld

        # ── binutils pass-through wrappers ────────────────────────────
        for tool in ar as nm objcopy objdump ranlib readelf size strings strip; do
          ${cat} > $out/bin/$tool << TOOL_EOF
        #!${shell}
        exec ${binutils_}/bin/$tool "\$@"
        TOOL_EOF
          ${chmod} +x $out/bin/$tool
        done

        # ── nix-support metadata ──────────────────────────────────────
        ${echo} "${cc}"        > $out/nix-support/orig-cc
        ${echo} "${libc}"      > $out/nix-support/orig-libc
        # Multi-output glibc: $dev holds headers, $static holds .a archives.
        # Consumers that need either (e.g. envoy bazel, llvm clang config)
        # read these instead of computing them from $out's path.
        ${echo} "${libcDev}"    > $out/nix-support/orig-libc-dev
        ${echo} "${libcStatic}" > $out/nix-support/orig-libc-static
        ${echo} "${binutils_}" > $out/nix-support/orig-binutils
        ${echo} "${system}"    > $out/nix-support/system
        ${echo} "-idirafter ${libcDev}/include" > $out/nix-support/cc-cflags
        ${echo} "${ccLdFlags}" > $out/nix-support/cc-ldflags
        ${echo} "${dynamicLinker}" > $out/nix-support/dynamic-linker
      ''
    ];
  };
in
  wrapperDrv
  // {
    inherit cc libc;
    binutils = binutils_;
    isWrapper = true;
    targetPrefix = "";
    inherit targetTriple;
    constraints = {
      build = null;
      execute = hostPlatform.constraints;
      target = hostPlatform.constraints;
    };
  }
