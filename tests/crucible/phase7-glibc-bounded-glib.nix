# Exercises the upstream provider's actual GLib and hidden formatter consumer.
{pkgs}: let
  runtime = pkgs.glibc-crucible;
  qualification = "${runtime}/share/glibc-crucible/qualification";
in
  pkgs.mkDerivation {
    pname = "glibc-crucible-glib-consumer";
    version = "2.39";
    src = null;
    buildDeps = [pkgs.crucible-cc pkgs.glib pkgs.binutils];
    phases = [
      {
        name = "compile-and-run-installed-consumer";
        script = ''
          ulimit -c 0
          ulimit -v 6291456
          test "$(cat ${qualification}/check-abi.status)" = 0
          mkdir -p "$out"

          # Use the exact source retained by this runtime's own source build.
          # Its real forked failure controls distinguish fail-stop exit 127
          # from recursive GLib logging (126) and an unexpected return (125).
          cp ${qualification}/tst-malloc-bounded-glib.c "$out/consumer.c"
          compile_status=0
          timeout -s KILL 180 ${pkgs.crucible-cc}/bin/gcc \
            -D_GNU_SOURCE -std=c11 -O2 -Wall -Wextra -Werror \
            -I${pkgs.glib.dev}/include/glib-2.0 \
            -I${pkgs.glib.dev}/lib/glib-2.0/include \
            "$out/consumer.c" ${pkgs.glib}/lib/libglib-2.0.so.0 \
            -Wl,-rpath,${pkgs.glib}/lib -ldl \
            -o "$out/consumer" > "$out/compile.log" 2>&1 || compile_status=$?
          cat "$out/compile.log"
          printf '%s\n' "$compile_status" > "$out/compile.status"
          test "$compile_status" = 0

          ${pkgs.binutils}/bin/readelf --program-headers --wide \
            "$out/consumer" > "$out/program-headers"
          interpreter="$(cat "$out/program-headers")"
          case "$interpreter" in
            *"[Requesting program interpreter: ${runtime}/lib/ld-linux-x86-64.so.2]"*) ;;
            *) echo "GLib consumer selected a different loader" >&2; exit 1 ;;
          esac

          ${runtime}/lib/ld-linux-x86-64.so.2 --list \
            "$out/consumer" > "$out/libraries"
          libraries="$(cat "$out/libraries")"
          case "$libraries" in
            *"libc.so.6 => ${runtime}/lib/libc.so.6 "*) ;;
            *) echo "GLib consumer selected a different libc" >&2; exit 1 ;;
          esac

          run_status=0
          timeout -s KILL 30 "$out/consumer" \
            > "$out/run.log" 2>&1 || run_status=$?
          cat "$out/run.log"
          printf '%s\n' "$run_status" > "$out/run.status"
          test "$run_status" = 0
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
