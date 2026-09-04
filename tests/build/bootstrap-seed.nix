# tests/build/bootstrap-seed.nix — Audit the compiler-bootstrap seed
#
# This gate reconstructs the committed binary from both maintained source
# forms, exercises the parser and file contract, injects syscall failures, and
# pins the immediate products that inherit trust from the seed.
{pkgs}: let
  seed = ../../stdenv/bootstrap/seeds/hex0;
  canonicalSource = ../../stdenv/bootstrap/seeds/hex0-i386.hex0;
  assemblySource = ../../stdenv/bootstrap/seeds/hex0-i386.S;
  kaemSource = ../../stdenv/bootstrap/seeds/kaem-nix.hex0;
  mkdirSource = ../../stdenv/bootstrap/seeds/mkdir.hex0;
  lnSource = ../../stdenv/bootstrap/seeds/ln.hex0;
  expectedSeedHash = "b7f8a8558f76c744b90c7e20b5e1edc6c89b57ba5edd3e727a256fcae2ea68ab";
in
  pkgs.mkDerivation {
    pname = "aos-bootstrap-seed-check";
    version = "1";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.diffutils
      pkgs.grep
      pkgs.strace
    ];

    outputChecks = {};
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          seed=${seed}
          canonical_source=${canonicalSource}
          assembly_source=${assemblySource}
          audit_dir=$TMPDIR/bootstrap-seed-audit
          mkdir -p "$audit_dir"

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          expect_decode_failure() {
            name=$1
            input=$2
            output="$audit_dir/$name.out"
            stdout="$audit_dir/$name.stdout"
            stderr="$audit_dir/$name.stderr"

            if "$seed" "$input" "$output" >"$stdout" 2>"$stderr"; then
              status=0
            else
              status=$?
            fi
            test "$status" = 1 || fail "$name returned status $status instead of 1"
            test ! -s "$stdout" || fail "$name wrote to standard output"
            test ! -s "$stderr" || fail "$name wrote to standard error"
            if test -e "$output" || test -L "$output"; then
              fail "$name left a partial output"
            fi
          }

          run_injected_success() {
            name=$1
            syscall=$2
            injection=$3
            output="$audit_dir/$name.out"
            trace="$audit_dir/$name.trace"

            strace -qq -o "$trace" \
              -e "trace=$syscall" -e "inject=$injection" \
              "$seed" "$canonical_source" "$output"
            grep -q INJECTED "$trace" || fail "$name did not inject a fault"
            cmp "$seed" "$output" || fail "$name changed the output"
          }

          run_injected_failure() {
            name=$1
            syscall=$2
            injection=$3
            input=$4
            output="$audit_dir/$name.out"
            trace="$audit_dir/$name.trace"

            if strace -qq -o "$trace" \
              -e "trace=$syscall" -e "inject=$injection" \
              "$seed" "$input" "$output"
            then
              status=0
            else
              status=$?
            fi
            test "$status" = 1 || fail "$name returned status $status instead of 1"
            grep -q INJECTED "$trace" || fail "$name did not inject a fault"
            if test -e "$output" || test -L "$output"; then
              fail "$name left a partial output"
            fi
          }

          echo "==> Checking the committed ELF"
          test -x "$seed" || fail "seed is not executable"
          test "$(stat -c %s "$seed")" = 501 || fail "seed size is not 501 bytes"
          echo "${expectedSeedHash}  $seed" | sha256sum -c -

          readelf -hW "$seed" > "$audit_dir/elf-header"
          grep -Eq 'Class:[[:space:]]+ELF32$' "$audit_dir/elf-header"
          grep -Eq 'Data:[[:space:]]+2.s complement, little endian$' "$audit_dir/elf-header"
          grep -Eq 'Type:[[:space:]]+EXEC ' "$audit_dir/elf-header"
          grep -Eq 'Machine:[[:space:]]+Intel 80386$' "$audit_dir/elf-header"
          grep -Eq 'Entry point address:[[:space:]]+0x8048074$' "$audit_dir/elf-header"
          grep -Eq 'Number of program headers:[[:space:]]+2$' "$audit_dir/elf-header"
          grep -Eq 'Number of section headers:[[:space:]]+0$' "$audit_dir/elf-header"

          readelf -lW "$seed" > "$audit_dir/program-headers"
          grep -Eq 'LOAD[[:space:]]+0x000000.*0x001f5 0x001f5 R E 0x1000$' "$audit_dir/program-headers"
          grep -Eq 'GNU_STACK[[:space:]]+0x000000.*0x00000 0x00000 RW[[:space:]]+0x10$' "$audit_dir/program-headers"
          if grep -Eq 'INTERP|DYNAMIC|RWE' "$audit_dir/program-headers"; then
            fail "seed has an interpreter, dynamic segment, or executable writable memory"
          fi
          readelf -SW "$seed" > "$audit_dir/sections"
          grep -q 'There are no sections in this file' "$audit_dir/sections"

          echo "==> Reconstructing both maintained source forms"
          "$seed" "$canonical_source" "$audit_dir/self-hosted"
          cmp "$seed" "$audit_dir/self-hosted"

          cc -D_POSIX_C_SOURCE=200809L -std=c99 -Wall -Wextra -Werror \
            ${./bootstrap-seed-reference.c} -o "$audit_dir/reference-decoder"
          "$audit_dir/reference-decoder" "$canonical_source" "$audit_dir/reference"
          cmp "$seed" "$audit_dir/reference"

          compare_decoders() {
            name=$1
            input=$2
            seed_output="$audit_dir/$name.seed"
            reference_output="$audit_dir/$name.reference"

            if "$seed" "$input" "$seed_output"; then
              seed_status=0
            else
              seed_status=$?
            fi
            if "$audit_dir/reference-decoder" "$input" "$reference_output"; then
              reference_status=0
            else
              reference_status=$?
            fi

            case $seed_status in 0 | 1) ;; *) fail "$name: seed returned $seed_status" ;; esac
            case $reference_status in 0 | 1) ;; *) fail "$name: reference returned $reference_status" ;; esac
            test "$seed_status" = "$reference_status" ||
              fail "$name: seed returned $seed_status, reference returned $reference_status"

            if test "$seed_status" = 0; then
              cmp "$seed_output" "$reference_output" ||
                fail "$name: successful outputs differ"
            else
              if test -e "$seed_output" || test -L "$seed_output"; then
                fail "$name: seed left a rejected output"
              fi
              if test -e "$reference_output" || test -L "$reference_output"; then
                fail "$name: reference left a rejected output"
              fi
            fi

            rm -f "$seed_output" "$reference_output"
          }

          value=0
          while test "$value" -lt 256; do
            octal=$(printf '%03o' "$value")
            printf '%b' "\\0$octal" > "$audit_dir/one-byte"
            compare_decoders "one-byte-$value" "$audit_dir/one-byte"

            printf '0%b' "\\0$octal" > "$audit_dir/low-nibble-byte"
            compare_decoders "low-nibble-byte-$value" "$audit_dir/low-nibble-byte"

            printf '%b11' "\\0$octal" > "$audit_dir/byte-before-pair"
            compare_decoders "byte-before-pair-$value" "$audit_dir/byte-before-pair"
            value=$((value + 1))
          done

          printf '4142G' > "$audit_dir/partial-invalid"
          compare_decoders partial-invalid "$audit_dir/partial-invalid"

          as --32 "$assembly_source" -o "$audit_dir/seed-code.o"
          readelf -rW "$audit_dir/seed-code.o" > "$audit_dir/relocations"
          grep -q 'There are no relocations in this file' "$audit_dir/relocations"
          objcopy -O binary --only-section=.text \
            "$audit_dir/seed-code.o" "$audit_dir/assembled-text"
          test "$(stat -c %s "$audit_dir/assembled-text")" = 385
          dd if="$seed" of="$audit_dir/seed-text" bs=1 skip=116 status=none
          cmp "$audit_dir/assembled-text" "$audit_dir/seed-text"

          echo "==> Exercising accepted input"
          printf '# leading comment\n00 ff A5 4# split byte\n1; comment at EOF' \
            > "$audit_dir/valid.hex0"
          printf '\000\377\245\101' > "$audit_dir/valid.expected"
          "$seed" "$audit_dir/valid.hex0" "$audit_dir/valid.out" \
            >"$audit_dir/valid.stdout" 2>"$audit_dir/valid.stderr"
          cmp "$audit_dir/valid.expected" "$audit_dir/valid.out"
          test ! -s "$audit_dir/valid.stdout"
          test ! -s "$audit_dir/valid.stderr"

          printf '0\t0 0\n1 0\r2' > "$audit_dir/separators.hex0"
          printf '\000\001\002' > "$audit_dir/separators.expected"
          "$seed" "$audit_dir/separators.hex0" "$audit_dir/separators.out"
          cmp "$audit_dir/separators.expected" "$audit_dir/separators.out"

          : > "$audit_dir/empty.hex0"
          "$seed" "$audit_dir/empty.hex0" "$audit_dir/empty.out"
          test ! -s "$audit_dir/empty.out"

          echo "==> Exercising rejection and file safety"
          printf '4G' > "$audit_dir/invalid.hex0"
          printf '4' > "$audit_dir/odd.hex0"
          printf '4# comment\n' > "$audit_dir/comment-odd.hex0"
          printf '41\01342' > "$audit_dir/bad-separator.hex0"
          expect_decode_failure invalid-byte "$audit_dir/invalid.hex0"
          expect_decode_failure odd-nibble "$audit_dir/odd.hex0"
          expect_decode_failure comment-odd "$audit_dir/comment-odd.hex0"
          expect_decode_failure bad-separator "$audit_dir/bad-separator.hex0"
          expect_decode_failure missing-input "$audit_dir/does-not-exist"

          if "$seed"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "zero-argument invocation returned $status"
          if "$seed" "$canonical_source"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "one-argument invocation returned $status"
          if "$seed" "$canonical_source" "$audit_dir/args.out" extra; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "extra-argument invocation returned $status"
          if test -e "$audit_dir/args.out" || test -L "$audit_dir/args.out"; then
            fail "extra-argument invocation created an output"
          fi

          printf 'preserve-existing' > "$audit_dir/existing.out"
          if "$seed" "$canonical_source" "$audit_dir/existing.out"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "existing output returned status $status"
          test "$(cat "$audit_dir/existing.out")" = preserve-existing

          cp "$canonical_source" "$audit_dir/same-path.hex0"
          cp "$audit_dir/same-path.hex0" "$audit_dir/same-path.saved"
          if "$seed" "$audit_dir/same-path.hex0" "$audit_dir/same-path.hex0"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "same-path invocation returned status $status"
          cmp "$audit_dir/same-path.saved" "$audit_dir/same-path.hex0"

          printf 'preserve-target' > "$audit_dir/symlink-target"
          ln -s "$audit_dir/symlink-target" "$audit_dir/symlink-output"
          if "$seed" "$canonical_source" "$audit_dir/symlink-output"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "symlink output returned status $status"
          test -L "$audit_dir/symlink-output"
          test "$(cat "$audit_dir/symlink-target")" = preserve-target

          ln -s "$audit_dir/dangling-target" "$audit_dir/dangling-output"
          if "$seed" "$canonical_source" "$audit_dir/dangling-output"; then
            status=0
          else
            status=$?
          fi
          test "$status" = 1 || fail "dangling symlink returned status $status"
          test -L "$audit_dir/dangling-output"
          test ! -e "$audit_dir/dangling-target"

          (
            umask 0777
            "$seed" "$canonical_source" "$audit_dir/restrictive-umask.out"
          )
          test "$(stat -c %a "$audit_dir/restrictive-umask.out")" = 700

          cc -D_POSIX_C_SOURCE=200809L -std=c99 -Wall -Wextra -Werror \
            ${./bootstrap-seed-high-fd.c} -o "$audit_dir/high-fd"
          "$audit_dir/high-fd" "$seed" "$canonical_source" "$audit_dir/high-fd.out"
          cmp "$seed" "$audit_dir/high-fd.out"

          echo "==> Injecting syscall interruption and failure"
          run_injected_success read-eintr read 'read:error=EINTR:when=1'
          run_injected_success write-eintr write 'write:error=EINTR:when=1'
          run_injected_success fsync-eintr fsync 'fsync:error=EINTR:when=1'
          run_injected_failure read-eio read 'read:error=EIO:when=1' "$canonical_source"
          run_injected_failure write-enospc write 'write:error=ENOSPC:when=1' "$canonical_source"
          run_injected_failure write-zero write 'write:retval=0:when=1' "$canonical_source"
          run_injected_failure fchmod-eperm fchmod 'fchmod:error=EPERM:when=1' "$canonical_source"
          run_injected_failure fsync-eio fsync 'fsync:error=EIO:when=1' "$canonical_source"
          run_injected_failure close-eio close 'close:error=EIO:when=1' "$canonical_source"
          run_injected_failure unlink-eintr unlink 'unlink:error=EINTR:when=1' "$audit_dir/invalid.hex0"

          echo "==> Pinning immediate bootstrap products"
          "$seed" ${kaemSource} "$audit_dir/kaem-nix"
          echo "7d2e4259ba2b614a1744ed255d3e6376ee4b231fbed34dce921eca72a8da30c1  $audit_dir/kaem-nix" |
            sha256sum -c -
          "$seed" ${mkdirSource} "$audit_dir/mkdir"
          echo "c4183f760bc75eb3aa3d69430ddebe3cad395ce24d64b744eb744ee781e67cd3  $audit_dir/mkdir" |
            sha256sum -c -
          "$seed" ${lnSource} "$audit_dir/ln"
          echo "706e39c9985fb5bcadcf423f13cbd9c3922f557a8eb72d9862b95a128fb314f5  $audit_dir/ln" |
            sha256sum -c -

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Audit the AOS compiler-bootstrap seed";
      license = "Apache-2.0";
      build = {
        os = "linux";
        cpu = "x86_64";
      };
      execute = {
        os = "linux";
        cpu = "x86_64";
      };
    };
  }
