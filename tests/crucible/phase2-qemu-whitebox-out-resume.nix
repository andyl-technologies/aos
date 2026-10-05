# Actual TCG/production-plugin stop/resume probe, without a Linux boot workload.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  flight = pkgs.mkCargoPackage {
    pname = "crucible-whitebox-out-resume-flight";
    version = "0";
    src = source;
    inherit cargoDeps;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --frozen --offline --release -p crucible-qemu --example crucible-qemu-whitebox-out-resume"
    ];
    doCheck = false;
    installBins = false;
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    dontStrip = true;
    dontPatchELF = true;
    buildDeps = [pkgs.coreutils pkgs.pkg-config];
    runtimeDeps = [pkgs.sqlite];
    postInstall = ''
      binary=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "crucible-qemu-whitebox-out-resume" and .target.kind == ["example"] and .profile.test == false and .executable != null) | .executable' \
        "$NIX_BUILD_TOP/cargo-build-messages.jsonl")
      test -f "$binary"
      mkdir -p "$out/bin"
      cp "$binary" "$out/bin/crucible-qemu-whitebox-out-resume"
    '';
  };
  guest = pkgs.mkDerivation {
    pname = "crucible-whitebox-out-resume-rom";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils flight];
    phases = [
      {
        name = "encode-and-build-roms";
        script = ''
          set -eu
          mkdir -p "$out"
          for mode in normal late-register; do
            ${flight}/bin/crucible-qemu-whitebox-out-resume firmware "$mode" "$mode"
            (
              cd "$mode"
              as --32 bios.S -o bios.o
              ld -m elf_i386 -nostdlib -T bios.ld -o bios.elf bios.o
              objcopy -O binary bios.elf "$out/$mode.bin"
            )
            test "$(wc -c < "$out/$mode.bin")" -eq 65536
          done
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmTest = testing.mkVMTest {
    name = "crucible-whitebox-out-resume";
    memory = 3072;
    rootfsDeps = [
      flight
      guest
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
    ];
    testScript = ''
      set -eu
      export TMPDIR=/tmp
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control
      truncate -s 2G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts

      for mode in normal late-register; do
        mkdir -m 700 "/tmp/attempts/$mode"
        if ${pkgs.coreutils}/bin/timeout -k 15 90 \
          ${flight}/bin/crucible-qemu-whitebox-out-resume run \
          ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
          ${guest}/"$mode.bin" /sys/fs/cgroup/crucible "/tmp/attempts/$mode" "$mode" \
          > "/tmp/$mode.result" 2> "/tmp/$mode.log"; then
          :
        else
          status=$?
          cat "/tmp/$mode.result" >&2
          tail -c 16384 "/tmp/$mode.log" >&2
          exit "$status"
        fi
        grep -Fxq PASS "/tmp/$mode.result"
        grep -Fxq 'owned_cleanup=complete' "/tmp/$mode.result"
      done
      grep -Fxq 'registration_sequence=1' /tmp/normal.result
      grep -Fxq 'request_sequences=2,3' /tmp/normal.result
      grep -Fxq 'distinct_semantic_frames=first,second' /tmp/normal.result
      grep -Fxq 'same_guest_buffer=20480' /tmp/normal.result
      grep -Fxq 'late_register_step_refused=true' /tmp/late-register.result
      test "$(grep -Fc 'selectable registration arrived after catalog freeze; kind=register id=out.ready seq=1 prev=1 done=2' /tmp/late-register.log)" -eq 1
      # Both owned processes are reaped before forwarding diagnostic tails.
      for mode in normal late-register; do
        echo "CRUCIBLE_OUT_RESUME_STDERR_''${mode}_BEGIN"
        echo "original_bytes=$(wc -c < "/tmp/$mode.log")"
        tail -c 16384 "/tmp/$mode.log" > "/tmp/$mode.stderr-tail"
        ${pkgs.coreutils}/bin/base64 -w 0 "/tmp/$mode.stderr-tail"
        printf '\n'
        echo "CRUCIBLE_OUT_RESUME_STDERR_''${mode}_END"
      done
      echo CRUCIBLE_OUT_RESUME_RESULT_BEGIN
      cat /tmp/normal.result /tmp/late-register.result
      echo 'original_late_registration_refusal=true'
      echo CRUCIBLE_OUT_RESUME_RESULT_END
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-whitebox-out-resume";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.gawk pkgs.grep pkgs.sed vmTest];
    passthru = {inherit flight guest vmTest;};
    phases = [
      {
        name = "retain-result";
        script = ''
          set -eu
          mkdir -p "$out"
          sed 's/\r$//' "${vmTest}/serial.log" > "$out/vm-serial.log"
          cp "${vmTest}/fc.log" "$out/vm-monitor.log"
          test "$(grep -Fxc CRUCIBLE_OUT_RESUME_RESULT_BEGIN "$out/vm-serial.log")" -eq 1
          test "$(grep -Fxc CRUCIBLE_OUT_RESUME_RESULT_END "$out/vm-serial.log")" -eq 1
          sed -n '/^CRUCIBLE_OUT_RESUME_RESULT_BEGIN$/,/^CRUCIBLE_OUT_RESUME_RESULT_END$/ {
            /^CRUCIBLE_OUT_RESUME_RESULT_/d
            p
          }' "$out/vm-serial.log" > "$out/result"
          # Each frame carries one original byte count and one encoded tail.
          for mode in normal late-register; do
            begin="CRUCIBLE_OUT_RESUME_STDERR_''${mode}_BEGIN"
            end="CRUCIBLE_OUT_RESUME_STDERR_''${mode}_END"
            awk -v begin="$begin" -v end="$end" '
              $0 == begin {
                if (state != 0) exit 1
                state = 1
                next
              }
              $0 == end {
                if (state != 1 || payload_lines != 2) exit 1
                state = 2
                next
              }
              state == 1 {
                if (payload_lines == 0 && $0 !~ /^original_bytes=(0|[1-9][0-9]*)$/) exit 1
                if (payload_lines == 1 && (length($0) > 21848 || $0 !~ /^[A-Za-z0-9+\/=]*$/)) exit 1
                if (payload_lines >= 2) exit 1
                print
                payload_lines += 1
              }
              END { if (state != 2) exit 1 }
            ' "$out/vm-serial.log" > "$TMPDIR/$mode.stderr-frame"
            original_bytes=$(sed -n '1s/^original_bytes=//p' "$TMPDIR/$mode.stderr-frame")
            sed -n '2p' "$TMPDIR/$mode.stderr-frame" \
              | ${pkgs.coreutils}/bin/base64 -d > "$out/$mode.stderr.log"
            retained_bytes=$(wc -c < "$out/$mode.stderr.log")
            test "$retained_bytes" -le 16384
            if test "$original_bytes" -gt 16384; then
              test "$retained_bytes" -eq 16384
              truncated=true
            else
              test "$retained_bytes" -eq "$original_bytes"
              truncated=false
            fi
            printf 'capture=tail\nmaximum_bytes=16384\noriginal_bytes=%s\nretained_bytes=%s\ntruncated=%s\n' \
              "$original_bytes" "$retained_bytes" "$truncated" > "$out/$mode.stderr.scope"
          done
          test "$(grep -Fxc PASS "$out/result")" -eq 2
          grep -Fxq 'original_late_registration_refusal=true' "$out/result"
        '';
      }
    ];
  }
