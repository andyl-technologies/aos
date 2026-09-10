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
        mkdir -p "$out/bin"

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
          link_flags="-L${libcStatic}/lib -L${glibc}/lib -B${glibc}/lib/"
          if [ "\$executable" = true ]; then
            link_flags="\$link_flags -static${
          if staticNoPie
          then " -no-pie"
          else ""
        }"
          fi
        fi
        exec ${compiler}/bin/$driver $header_flags -B${binutils}/bin/ "\$@" \$link_flags
        WRAPPER
          chmod 755 "$out/bin/$driver"
        done
        ln -s gcc "$out/bin/cc"
        if [ -x "$out/bin/g++" ]; then
          ln -s g++ "$out/bin/c++"
        fi
      ''
    ];
  }
  // {
    meta = compiler.meta or {};
    passthru.constructionCompiler = compiler;
  }
