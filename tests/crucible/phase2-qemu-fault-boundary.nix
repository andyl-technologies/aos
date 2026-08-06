{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName,
  attrPath ? "checks.crucible.phase2.qemuFaultBoundary",
  taskIds ? ["T-QEMU-0047" "T-QEMU-0048"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  pluginSource = builtins.readFile ./phase2-qemu-fault-boundary.c;
  isAarch64 = lib.platform.system == "aarch64-linux";
  guestSourcePath =
    if isAarch64
    then ./phase2-qemu-fault-guest-aarch64.S
    else ./phase2-qemu-fault-guest.S;
  guestLinkerPath =
    if isAarch64
    then ./phase2-qemu-fault-guest-aarch64.ld
    else ./phase2-qemu-fault-guest.ld;
  guestSource = builtins.readFile guestSourcePath;
  guestLinker = builtins.readFile guestLinkerPath;
  qemuBinary =
    if isAarch64
    then "qemu-system-aarch64"
    else "qemu-system-x86_64";
  qemuMachineArgs =
    if isAarch64
    then "-machine virt -cpu max -m 64M"
    else "-machine pc -m 16M";
  guestBuild =
    if isAarch64
    then ''
      as ${guestSourcePath} -o fault-guest.o
      ld -T ${guestLinkerPath} fault-guest.o -o fault-guest.elf
    ''
    else ''
      as --32 ${guestSourcePath} -o fault-guest.o
      ld -m elf_i386 -T ${guestLinkerPath} fault-guest.o -o fault-guest.elf
    '';
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource (
      if patchName == "0047-crucible-fault-command-abi.patch"
      then [
        {
          label = "public capability query";
          needle = "qemu_plugin_crucible_fault_capabilities";
        }
        {
          label = "public command submission";
          needle = "qemu_plugin_crucible_fault_submit";
        }
        {
          label = "public result polling";
          needle = "qemu_plugin_crucible_fault_poll";
        }
      ]
      else [
        {
          label = "exact boundary budget clamp";
          needle = "qemu_crucible_fault_clamp_budget";
        }
        {
          label = "node-boundary dispatch";
          needle = "CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY";
        }
        {
          label = "post-execution exact-boundary dispatch";
          needle = "qemu_crucible_fault_dispatch_boundary(";
        }
      ]
    )
    ++ failuresFor "tests/crucible/phase2-qemu-fault-boundary.c" pluginSource [
      {
        label = "live capability query";
        needle = "qemu_plugin_crucible_fault_capabilities(NULL, 0)";
      }
      {
        label = "live exact-boundary assertion";
        needle = "result.observed_icount != target_icount";
      }
      {
        label = "live application-boundary assertion";
        needle = "result.applied_icount != target_icount";
      }
      {
        label = "live pass marker";
        needle = "CRUCIBLE_FAULT_BOUNDARY_LIVE_PASS";
      }
    ]
    ++ failuresFor "selected fault test guest assembly" guestSource [
      {
        label = "real executing guest loop";
        needle =
          if isAarch64
          then "b 1b"
          else "jmp 1b";
      }
    ]
    ++ failuresFor "selected fault test guest linker script" guestLinker [
      {
        label = "architecture-specific guest load address";
        needle =
          if isAarch64
          then ". = 0x40200000;"
          else ". = 0x00100000;";
      }
    ];
in
  if failures != []
  then throw "Crucible live QEMU fault-boundary microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-fault-boundary-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.grep
        pkgs.pkg-config
        qemuPackage
        referenceQemu
      ];

      phases = [
        {
          name = "build-live-fixtures";
          script = ''
            set -eu
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-fault-boundary.c} \
              -o fault-boundary.so \
              $(pkg-config --libs glib-2.0)
            ${guestBuild}
          '';
        }
        {
          name = "run-live-boundary";
          script = ''
            set -eu
            set +e
            timeout 5 ${qemuPackage}/bin/${qemuBinary} \
              ${qemuMachineArgs} \
              -accel sim \
              -icount shift=0 \
              -smp 1 \
              -nographic \
              -no-reboot \
              -serial none \
              -monitor none \
              -kernel fault-guest.elf \
              -plugin "$PWD/fault-boundary.so" \
              > patched.log 2>&1
            patched_status=$?
            set -e
            cat patched.log
            test "$patched_status" -eq 124
            grep -Fxq CRUCIBLE_FAULT_BOUNDARY_LIVE_PASS patched.log
            test "$(grep -Fc CRUCIBLE_FAULT_BOUNDARY_LIVE_PASS patched.log)" -eq 1
            ! grep -q CRUCIBLE_FAULT_BOUNDARY_LIVE_FAIL patched.log

            set +e
            timeout 5 ${referenceQemu}/bin/${qemuBinary} \
              ${qemuMachineArgs} \
              -accel tcg \
              -icount shift=0 \
              -smp 1 \
              -nographic \
              -no-reboot \
              -serial none \
              -monitor none \
              -kernel fault-guest.elf \
              -plugin "$PWD/fault-boundary.so" \
              > stock.log 2>&1
            stock_status=$?
            set -e
            cat stock.log
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            ! grep -q CRUCIBLE_FAULT_BOUNDARY_LIVE_PASS stock.log
            ! nm -D --defined-only \
              ${referenceQemu}/bin/${qemuBinary} \
              | grep -q qemu_plugin_crucible_fault_submit

            mkdir -p "$out"
            cp patched.log stock.log "$out/"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'patch=%s\n' '${patchName}'
              printf 'patched_fixture_exercised=true\n'
              printf 'stock_negative_control=true\n'
              printf 'qemu_package=%s\n' '${qemuPackage}'
              printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
              printf 'attr_path=%s\n' '${attrPath}'
              printf 'task_ids=%s\n' '${taskList}'
              printf 'backend=actual-patched-and-stock-qemu\n'
            } > "$out/result"
          '';
        }
      ];
    }
