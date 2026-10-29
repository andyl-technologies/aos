##! Behavior of `toolchain-cache-check` against recorded Nix output.
##!
##! A stub replaces `nix`: it records its arguments and replays a dry-run
##! report chosen by `STUB_SCENARIO`. The cases cover a fully substitutable
##! set, a set with local builds, paths Nix cannot realize, a failing Nix
##! command, system selection, a separate store, and the `--max-jobs 0`
##! realization mode.
{pkgs}: let
  # Two trivial derivations stand in for each system's toolchain set; the
  # check embeds only their `.drv` paths.
  fakeToolchain = system: name:
    pkgs.writeTextFile {
      name = "fake-${system}-${name}";
      text = name;
    };
  toolchainSets = {
    x86_64-linux = {
      cc = fakeToolchain "x86_64-linux" "cc";
      go = fakeToolchain "x86_64-linux" "go";
    };
    aarch64-linux = {
      cc = fakeToolchain "aarch64-linux" "cc";
    };
  };

  stubNix = pkgs.writeShellScriptBin "nix" ''
    printf '%s\n' "$*" >> "$STUB_LOG"
    case "$STUB_SCENARIO" in
      substitutable)
        printf '%s\n' \
          'these 2 paths will be fetched (10.0 MiB download, 50.0 MiB unpacked):' \
          '  /nix/store/00000000000000000000000000000000-cc' \
          '  /nix/store/11111111111111111111111111111111-go' >&2
        ;;
      builds)
        printf '%s\n' \
          'these 2 derivations will be built:' \
          '  /nix/store/22222222222222222222222222222222-go.drv' \
          '  /nix/store/33333333333333333333333333333333-cc.drv' \
          'these 1 paths will be fetched (1.0 MiB download, 2.0 MiB unpacked):' \
          '  /nix/store/44444444444444444444444444444444-glibc' >&2
        ;;
      unknown)
        printf '%s\n' \
          "don't know how to build these paths:" \
          '  /nix/store/55555555555555555555555555555555-cc.drv' >&2
        ;;
      fails)
        echo 'error: cannot connect to the daemon' >&2
        exit 1
        ;;
    esac
  '';

  check = import ../../tools/toolchain-cache-check {
    inherit pkgs toolchainSets;
    inherit (pkgs) lib;
    nixExecutable = "${stubNix}/bin/nix";
  };
in
  pkgs.mkDerivation {
    pname = "aos-toolchain-cache-check-test";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          export STUB_LOG="$TMPDIR/nix-arguments"
          run() {
            : > "$STUB_LOG"
            STUB_SCENARIO=$1
            shift
            export STUB_SCENARIO
            status=0
            ${check}/bin/toolchain-cache-check "$@" > "$TMPDIR/stdout" 2> "$TMPDIR/stderr" || status=$?
          }
          fail() {
            echo "toolchain-cache-check test: $*" >&2
            cat "$TMPDIR/stdout" "$TMPDIR/stderr" >&2
            exit 1
          }

          run substitutable
          [ "$status" -eq 0 ] || fail "substitutable set exited $status"
          grep -q -- '--dry-run' "$STUB_LOG" || fail "default mode did not dry-run"
          grep -q 'fake-x86_64-linux-cc.drv^\*' "$STUB_LOG" || fail "x86_64-linux set not requested"
          grep -q 'fake-aarch64-linux-cc.drv^\*' "$STUB_LOG" || fail "aarch64-linux set not requested"

          run builds
          [ "$status" -eq 1 ] || fail "local builds exited $status, expected 1"
          grep -q '2 derivations would be built locally' "$TMPDIR/stderr" || fail "build count missing"
          grep -q '22222222222222222222222222222222-go.drv' "$TMPDIR/stderr" || fail "built path missing"
          if grep -q '44444444444444444444444444444444-glibc' "$TMPDIR/stderr"; then
            fail "a fetched path was reported as a local build"
          fi

          run unknown
          [ "$status" -eq 2 ] || fail "unrealizable paths exited $status, expected 2"
          grep -q '55555555555555555555555555555555-cc.drv' "$TMPDIR/stderr" || fail "unrealizable path missing"

          run fails
          [ "$status" -eq 2 ] || fail "failing nix exited $status, expected 2"

          run substitutable --system aarch64-linux
          [ "$status" -eq 0 ] || fail "system selection exited $status"
          if grep -q 'fake-x86_64-linux' "$STUB_LOG"; then
            fail "an unselected system was requested"
          fi

          run substitutable --system riscv64-linux
          [ "$status" -eq 2 ] || fail "unknown system exited $status, expected 2"

          run substitutable --store /clean-store
          [ "$status" -eq 0 ] || fail "separate store exited $status"
          grep -q '^--extra-experimental-features nix-command copy --no-check-sigs --to /clean-store /nix/store/.*fake-x86_64-linux-cc.drv' "$STUB_LOG" ||
            fail "derivations were not copied into the separate store"
          grep -q -- 'build --no-link --store /clean-store' "$STUB_LOG" || fail "the build did not use the separate store"

          run substitutable --realise -- --option substituters https://cache.invalid/
          [ "$status" -eq 0 ] || fail "realization exited $status"
          grep -q -- '--max-jobs 0' "$STUB_LOG" || fail "realization allowed local builds"
          grep -q -- '--option substituters https://cache.invalid/' "$STUB_LOG" || fail "nix arguments were not forwarded"
          if grep -q -- '--dry-run' "$STUB_LOG"; then
            fail "realization ran a dry run"
          fi

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
