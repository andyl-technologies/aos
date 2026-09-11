##! Selects a new libc while rebuilding a tier with its construction compiler.
{
  compiler,
  gccVersion,
  glibc,
  binutils,
  buildTools,
  buildPlatform,
  hostPlatform,
  staticNoPie ? false,
}: let
  libcDev = glibc.dev or glibc;
  libcStatic = glibc.static or glibc;
in
  builtins.derivation {
    name = "gcc-${gccVersion}-for-tier-exports";
    system = buildPlatform.system;
    builder = "${buildTools.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${buildTools.coreutils}/bin:${buildTools.bash}/bin"
        mkdir -p "$out/bin" "$out/lib"

        # GCC loads an installed specs file after its built-in defaults. Copy
        # that file and retarget every glibc output before using the compiler;
        # command-line -L flags alone lose to paths prepended by *link.
        compiler_specs=$(${compiler}/bin/gcc -print-file-name=specs)
        if [ -f "$compiler_specs" ]; then
          cp "$compiler_specs" "$out/lib/gcc-retarget.specs"
        else
          ${compiler}/bin/gcc -dumpspecs > "$out/lib/gcc-retarget.specs"
        fi
        chmod u+w "$out/lib/gcc-retarget.specs"
        ${buildTools.sed}/bin/sed -r -i \
          -e 's|/nix/store/[a-z0-9]{32}-glibc-[^ /}%]+-static|${libcStatic}|g' \
          -e 's|/nix/store/[a-z0-9]{32}-glibc-[^ /}%]+-dev|${libcDev}|g' \
          -e 's|/nix/store/[a-z0-9]{32}-glibc-[^ /}%]+|${glibc}|g' \
          "$out/lib/gcc-retarget.specs"

        if ${buildTools.grep}/bin/grep -E '/nix/store/[a-z0-9]{32}-glibc-' "$out/lib/gcc-retarget.specs" \
          | ${buildTools.grep}/bin/grep -Fv -e '${glibc}' -e '${libcDev}' -e '${libcStatic}'; then
          echo "retargeted GCC specs still contain a construction glibc" >&2
          exit 1
        fi

        # An -idirafter override cannot replace headers baked into the compiler.
        # -isystem alone moves libc ahead of C++ headers and breaks include_next.
        # Keep compiler-owned headers first and exclude the old libc search dirs.
        builtin_headers=$(${compiler}/bin/gcc -print-file-name=include)
        test -d "$builtin_headers"
        fixed_headers=$(${compiler}/bin/gcc -print-file-name=include-fixed)

        for driver in gcc g++; do
          test -x "${compiler}/bin/$driver" || continue
          header_flags="-nostdinc"
          if [ "$driver" = g++ ]; then
            cxx_headers="${compiler}/include/c++/${gccVersion}"
            test -d "$cxx_headers"
            header_flags="$header_flags -isystem $cxx_headers"
            for directory in "$cxx_headers/${hostPlatform.config}" "$cxx_headers/backward"; do
              if [ -d "$directory" ]; then
                header_flags="$header_flags -isystem $directory"
              fi
            done
          fi
          header_flags="$header_flags -isystem $builtin_headers"
          if [ -d "$fixed_headers" ]; then
            header_flags="$header_flags -isystem $fixed_headers"
          fi
          header_flags="$header_flags -isystem ${libcDev}/include"

          cat > "$out/bin/$driver" <<WRAPPER
        #!${buildTools.bash}/bin/bash
        set -eu
        linking=true
        executable=true
        for argument in "\$@"; do
          case "\$argument" in
            -c|-S|-E) linking=false ;;
            -shared|-r|--relocatable|-nostdlib|-nostartfiles|-ffreestanding) executable=false ;;
          esac
        done

        link_flags=""
        if [ "\$linking" = true ]; then
          if [ "\$executable" = true ]; then
            link_flags="-static${
          if staticNoPie
          then " -no-pie"
          else ""
        }"
          fi
        fi
        exec ${compiler}/bin/$driver \
          -specs=$out/lib/gcc-retarget.specs \
          $header_flags \
          -B${binutils}/bin/ \
          -B${glibc}/lib/ \
          -B${libcStatic}/lib/ \
          "\$@" \$link_flags
        WRAPPER
          chmod 755 "$out/bin/$driver"
        done
        ln -s gcc "$out/bin/cc"
        if [ -x "$out/bin/g++" ]; then
          ln -s g++ "$out/bin/c++"
        fi

        selected_crt=$("$out/bin/gcc" -print-file-name=crt1.o)
        selected_libc=$("$out/bin/gcc" -print-file-name=libc.a)
        selected_ld=$("$out/bin/gcc" -print-prog-name=ld)
        test "$selected_crt" = "${glibc}/lib/crt1.o"
        test "$selected_libc" = "${libcStatic}/lib/libc.a"
        test "$selected_ld" = "${binutils}/bin/ld"

        printf 'int main(void) { return 0; }\n' > "$TMPDIR/retarget-probe.c"
        "$out/bin/gcc" -Wl,-t "$TMPDIR/retarget-probe.c" -o "$TMPDIR/retarget-probe" \
          > "$TMPDIR/retarget-link.trace" 2>&1
        ${buildTools.grep}/bin/grep -Fq '${libcStatic}/lib/libc.a' "$TMPDIR/retarget-link.trace"
        if ${buildTools.grep}/bin/grep -F "${compiler}/lib/gcc" "$TMPDIR/retarget-link.trace" \
          | ${buildTools.grep}/bin/grep -Fq '/libc.a'; then
          echo "retargeted GCC selected its construction libc archive" >&2
          exit 1
        fi
      ''
    ];
  }
  // {
    meta = compiler.meta or {};
    passthru.constructionCompiler = compiler;
  }
