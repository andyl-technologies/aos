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
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed vmTest];
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
          test "$(grep -Fxc PASS "$out/result")" -eq 2
          grep -Fxq 'original_late_registration_refusal=true' "$out/result"
        '';
      }
    ];
  }
