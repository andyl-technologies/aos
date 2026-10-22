##! Builds ordinary consumers against the matching bounded-thread libc outputs.
{
  stdenv,
  mkDerivation,
  glibc-crucible,
  sed,
}: let
  runtime = glibc-crucible;

  # GCC's tier-local specs put its construction libc before user -L flags.
  # Retarget those actual specs rather than mixing the two private TCB layouts.
  driver = mkDerivation {
    pname = "crucible-gcc-driver";
    version = "16.2.0";
    src = null;
    buildDeps = [sed];
    runtimeDeps = [stdenv.gcc runtime];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib"
          ${stdenv.gcc}/bin/gcc -dumpspecs > "$out/lib/specs"
          ${sed}/bin/sed -i \
            -e 's|${stdenv.glibc.dev}|${runtime.dev}|g' \
            -e 's|${stdenv.glibc.static}|${runtime.static}|g' \
            -e 's|${stdenv.glibc}|${runtime}|g' \
            "$out/lib/specs"

          for compiler in gcc g++; do
            cat > "$out/bin/$compiler" <<AOS_CRUCIBLE_CC
          #!${stdenv.shell}
          exec ${stdenv.gcc}/bin/$compiler -specs=$out/lib/specs "\$@"
          AOS_CRUCIBLE_CC
            chmod +x "$out/bin/$compiler"
          done
        '';
      }
    ];

    passthru.evidenceSources =
      [./crucible-cc.nix]
      ++ stdenv.gcc.passthru.evidenceSources;
    meta = {
      description = "GCC driver with matching bounded-thread libc specs";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  };

  wrapper = import ../../stdenv/cc-wrapper.nix {
    cc = driver;
    libc = runtime;
    binutils_ = stdenv.binutils;
    inherit (stdenv) coreutils hostPlatform buildPlatform;
    shell = stdenv.shell;
  };
in
  mkDerivation {
    pname = "crucible-cc";
    version = "16.2.0";
    inherit (runtime) platformSupport;
    src = null;
    buildDeps = [wrapper];
    runtimeDeps = [driver runtime stdenv.binutils];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -r ${wrapper}/. "$out/"
          # The package finalizer must add metadata to this copied store tree.
          chmod -R u+w "$out"
        '';
      }
      {
        name = "check";
        script = ''
          ulimit -c 0
          "$out/bin/gcc" -std=c11 -Wall -Wextra -Werror -pthread \
            ${./tests/crucible-cc-consumer.c} -o installed-consumer

          interpreter="$(${stdenv.binutils}/bin/readelf --program-headers --wide installed-consumer)"
          case "$interpreter" in
            *"[Requesting program interpreter: ${runtime}/lib/ld-linux-x86-64.so.2]"*) ;;
            *) echo "installed consumer selected a different loader" >&2; exit 1 ;;
          esac

          libraries="$(${runtime}/lib/ld-linux-x86-64.so.2 --list ./installed-consumer)"
          case "$libraries" in
            *"libc.so.6 => ${runtime}/lib/libc.so.6 "*) ;;
            *) echo "installed consumer selected a different libc" >&2; exit 1 ;;
          esac
          ./installed-consumer

          "$out/bin/g++" -std=c++17 -Wall -Wextra -Werror -x c++ -fsyntax-only - <<'AOS_BOUNDED_HEADER'
          #include <pthread-bounded.h>
          static_assert(sizeof(pthread_bounded_config) == 136);
          static_assert(sizeof(pthread_bounded_receipt) == 368);
          AOS_BOUNDED_HEADER
        '';
      }
    ];

    passthru =
      wrapper.passthru
      // {
        inherit (wrapper) cc libc binutils isWrapper targetPrefix targetTriple;
        evidenceSources = wrapper.passthru.evidenceSources ++ [./tests/crucible-cc-consumer.c];
      };
    meta = {
      description = "C and C++ compiler wrapper for the matching bounded-thread libc";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  }
