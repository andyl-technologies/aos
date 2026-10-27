# Exercises the installed loader's actual early allocation and refusal routes.
{pkgs}: let
  runtime = pkgs.glibc-crucible;
  qualification = "${runtime}/share/glibc-crucible/qualification";
in
  pkgs.mkDerivation {
    pname = "glibc-crucible-initial-loader";
    version = "2.39";
    src = null;
    buildDeps = [pkgs.crucible-cc pkgs.python3 pkgs.binutils pkgs.linux-headers];
    phases = [
      {
        name = "qualify-installed-initial-loader";
        script = ''
          ulimit -c 0
          ulimit -v 2097152
          test "$(cat ${qualification}/check-abi.status)" = 0
          mkdir -p "$out"

          # Keep this runtime's original fixture and runner with their notices.
          # Its ordinary control must execute the real IFUNC, constructor and
          # TLS entry; selected probes must refuse before any of those effects.
          cp ${qualification}/tst-bounded-initial-mod.c "$out/consumer.c"
          cp ${qualification}/tst-bounded-initial-launch.c "$out/launcher.c"
          cp ${qualification}/tst-bounded-initial.py "$out/controls.py"
          cp ${runtime.dev}/include/malloc-bounded-initial.h "$out/header.h"
          compile_status=0
          timeout -s KILL 180 ${pkgs.crucible-cc}/bin/gcc \
            -std=gnu11 -O2 -Wall -Wextra -Werror \
            "$out/consumer.c" -o "$out/consumer" \
            > "$out/compile.log" 2>&1 || compile_status=$?
          cat "$out/compile.log"
          printf '%s\n' "$compile_status" > "$out/compile.status"
          test "$compile_status" = 0

          launcher_status=0
          timeout -s KILL 180 ${pkgs.crucible-cc}/bin/gcc \
            -std=gnu11 -O2 -Wall -Wextra -Werror \
            -isystem ${pkgs.linux-headers}/include \
            "$out/launcher.c" -o "$out/launcher" \
            > "$out/launcher.log" 2>&1 || launcher_status=$?
          cat "$out/launcher.log"
          printf '%s\n' "$launcher_status" > "$out/launcher.status"
          test "$launcher_status" = 0

          header_status=0
          timeout -s KILL 180 ${pkgs.crucible-cc}/bin/g++ \
            -std=c++17 -Wall -Wextra -Werror -x c++ -fsyntax-only - \
            > "$out/header.log" 2>&1 <<'AOS_INITIAL_HEADER' || header_status=$?
          #include <cstddef>
          #include <malloc-bounded-initial.h>
          static_assert(sizeof(malloc_bounded_initial_config) == 128);
          static_assert(sizeof(malloc_bounded_initial_receipt) == 512);
          static_assert(sizeof(malloc_bounded_initial_record) == 64);
          static_assert(sizeof(malloc_bounded_initial_layout) == 256);
          static_assert(offsetof(malloc_bounded_initial_config, reserved) == 64);
          static_assert(offsetof(malloc_bounded_initial_receipt, reserved) == 352);
          static_assert(offsetof(malloc_bounded_initial_layout, reserved) == 224);
          AOS_INITIAL_HEADER
          cat "$out/header.log"
          printf '%s\n' "$header_status" > "$out/header.status"
          test "$header_status" = 0

          ${pkgs.binutils}/bin/readelf --program-headers --wide \
            "$out/consumer" > "$out/program-headers"
          interpreter="$(cat "$out/program-headers")"
          case "$interpreter" in
            *"[Requesting program interpreter: ${runtime}/lib/ld-linux-x86-64.so.2]"*) ;;
            *) echo "initial consumer selected a different loader" >&2; exit 1 ;;
          esac

          ${runtime}/lib/ld-linux-x86-64.so.2 --list \
            "$out/consumer" > "$out/libraries"
          libraries="$(cat "$out/libraries")"
          case "$libraries" in
            *"libc.so.6 => ${runtime}/lib/libc.so.6 "*) ;;
            *) echo "initial consumer selected a different libc" >&2; exit 1 ;;
          esac

          sha256sum ${runtime}/lib/ld-linux-x86-64.so.2 \
            ${runtime}/lib/libc.so.6 "$out/header.h" \
            "$out/consumer" "$out/launcher" "$out/controls.py" > "$out/inputs.sha256"

          # Preserve original child statuses, receipts, arenas and effect markers.
          # An expected probe exit 127 is a refusal, never process admission.
          run_status=0
          timeout -s KILL 120 ${pkgs.python3}/bin/python3 "$out/controls.py" \
            --loader ${runtime}/lib/ld-linux-x86-64.so.2 \
            --program "$out/consumer" --launcher "$out/launcher" \
            --library-path ${runtime}/lib \
            --directory "$out/initial-controls" \
            > "$out/run.log" 2>&1 || run_status=$?
          cat "$out/run.log"
          printf '%s\n' "$run_status" > "$out/run.status"
          test "$run_status" = 0
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
