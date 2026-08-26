# stdenv/darwin-cc-wrapper.nix — Linux-executed Darwin compiler wrappers
{
  llvm,
  sdk,
  runtimes ? null,
  shell,
  coreutils,
  buildPlatform,
  hostPlatform,
  deploymentTarget ? "11.0",
  sdkVersion ? "15.0",
  defaultHardening ? "",
}: let
  system = buildPlatform.system;
  targetTriple = hostPlatform.config;

  mkdir = "${coreutils}/bin/mkdir";
  cat = "${coreutils}/bin/cat";
  chmod = "${coreutils}/bin/chmod";
  dirname = "${coreutils}/bin/dirname";
  ln = "${coreutils}/bin/ln";
  echo = "${coreutils}/bin/echo";
  runtimeCompilerFlags =
    if runtimes == null
    then ""
    else "-isystem ${runtimes}/include/c++/v1";
  runtimeLinkerFlags =
    if runtimes == null
    then ""
    else "-L${runtimes}/lib -Wl,-rpath,${runtimes}/lib";
  wrapper = builtins.derivation {
    name = "aos-${hostPlatform.system}-cc-wrapper";
    inherit system;
    builder = shell;
    args = [
      "-c"
      ''
        set -eu

        ${mkdir} -p "$out/bin" "$out/nix-support"

        ${cat} > "$out/bin/clang" <<'WRAPPER_EOF'
        #!${shell}
        set -eu

        linking=true
        exec_link=true
        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
            -dynamiclib|-shared|-bundle|-r|--relocatable|-nostdlib|-nostartfiles|-ffreestanding) exec_link=false ;;
          esac
        done

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

        if has stackprotector; then
          hardening_cflags="$hardening_cflags -fstack-protector-strong"
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
        if has pacret; then
          hardening_cflags="$hardening_cflags -mbranch-protection=pac-ret"
        fi
        if has trivialautovarinit; then
          hardening_cflags="$hardening_cflags -ftrivial-auto-var-init=zero"
        fi
        if has zerocallusedregs; then
          hardening_cflags="$hardening_cflags -fzero-call-used-regs=used-gpr"
        fi

        if has fortify3; then
          hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
          hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
        elif has fortify; then
          hardening_cflags="$hardening_cflags -O2 -U_FORTIFY_SOURCE"
          hardening_post="$hardening_post -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
        fi

        if [ "$linking" = true ]; then
          if has pie && [ "$exec_link" = true ]; then
            hardening_ldflags="$hardening_ldflags -Wl,-pie"
          fi
          if has bindnow; then
            hardening_ldflags="$hardening_ldflags -Wl,-bind_at_load"
          fi
        fi

        nix_ldflags=""
        if [ "$linking" = true ] && [ -n "''${NIX_LDFLAGS:-}" ]; then
          nix_ldflags="$NIX_LDFLAGS"
        fi

        exec ${llvm}/bin/clang \
          --target=${targetTriple} \
          -isysroot ${sdk} \
          -mmacosx-version-min=${deploymentTarget} \
          -fuse-ld=lld \
          ${runtimeCompilerFlags} \
          $hardening_cflags \
          "$@" \
          $hardening_post \
          $hardening_ldflags \
          ${runtimeLinkerFlags} \
          $nix_ldflags
        WRAPPER_EOF
        ${chmod} +x "$out/bin/clang"

        ${cat} > "$out/bin/clang++" <<'WRAPPER_EOF'
        #!${shell}
        set -eu
        exec "$(${dirname} "$0")/clang" -stdlib=libc++ "$@"
        WRAPPER_EOF
        ${chmod} +x "$out/bin/clang++"

        # GCC's Darwin driver invokes an external `as`.  Clang's integrated
        # assembler is the hermetic Mach-O assembler until cctools is built.
        ${cat} > "$out/bin/as" <<'WRAPPER_EOF'
        #!${shell}
        set -eu
        exec ${llvm}/bin/clang \
          --target=${targetTriple} \
          -isysroot ${sdk} \
          -mmacosx-version-min=${deploymentTarget} \
          -c -x assembler "$@"
        WRAPPER_EOF
        ${chmod} +x "$out/bin/as"

        ${cat} > "$out/bin/ld" <<'WRAPPER_EOF'
        #!${shell}
        set -eu
        exec ${llvm}/bin/ld64.lld \
          -arch ${hostPlatform.darwinArch} \
          -syslibroot ${sdk} \
          -platform_version macos ${deploymentTarget} ${sdkVersion} \
          -L${sdk}/usr/lib \
          "$@"
        WRAPPER_EOF
        ${chmod} +x "$out/bin/ld"

        for alias in cc gcc; do
          ${ln} -s clang "$out/bin/$alias"
        done
        for alias in c++ g++; do
          ${ln} -s clang++ "$out/bin/$alias"
        done
        ${ln} -s ld "$out/bin/ld64"

        for alias in cc gcc clang; do
          ${ln} -s clang "$out/bin/${targetTriple}-$alias"
        done
        for alias in c++ g++ clang++; do
          ${ln} -s clang++ "$out/bin/${targetTriple}-$alias"
        done
        ${ln} -s ld "$out/bin/${targetTriple}-ld"
        ${ln} -s as "$out/bin/${targetTriple}-as"

        for tool in ar ranlib nm objcopy objdump size strings strip; do
          ${ln} -s "${llvm}/bin/llvm-$tool" "$out/bin/$tool"
          ${ln} -s "${llvm}/bin/llvm-$tool" "$out/bin/${targetTriple}-$tool"
        done

        for tool in lipo dwarfdump; do
          ${ln} -s "${llvm}/bin/llvm-$tool" "$out/bin/$tool"
          ${ln} -s "${llvm}/bin/llvm-$tool" "$out/bin/${targetTriple}-$tool"
        done
        ${ln} -s "${llvm}/bin/dsymutil" "$out/bin/dsymutil"
        ${ln} -s "${llvm}/bin/dsymutil" "$out/bin/${targetTriple}-dsymutil"

        ${echo} ${llvm} > "$out/nix-support/orig-cc"
        ${echo} ${sdk} > "$out/nix-support/orig-libc"
        ${echo} ${sdk} > "$out/nix-support/orig-libc-dev"
        ${echo} ${sdk} > "$out/nix-support/sysroot"
        ${echo} ${targetTriple} > "$out/nix-support/target-config"
        ${echo} ${deploymentTarget} > "$out/nix-support/deployment-target"
      ''
    ];
  };
in
  wrapper
  // {
    passthru = {
      inherit llvm sdk runtimes hostPlatform targetTriple deploymentTarget sdkVersion;
      libc = sdk;
    };
    meta = {
      execute = buildPlatform.constraints;
      target = hostPlatform.constraints;
    };
    constraints = {
      build = buildPlatform.constraints;
      execute = buildPlatform.constraints;
      target = hostPlatform.constraints;
    };
  }
