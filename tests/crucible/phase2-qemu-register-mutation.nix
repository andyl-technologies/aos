{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0051-crucible-add-architecture-register-fault-mutations.patch",
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "architecture-owned register descriptors";
        needle = "crucible_register_describe";
      }
      {
        label = "exact instruction boundary handling";
        needle = "qemu_crucible_fault_register_instruction_boundary";
      }
      {
        label = "post-write architectural readback";
        needle = "memcmp(after->data, desired, bytes)";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "GDB mutation shortcut";
        needle = "gdb_write_register";
      }
      {
        label = "native CPU-state offset in public manifest";
        needle = "fieldoffset";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU register-mutation microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-register-mutation";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.glib pkgs.gnugrep pkgs.llvm pkgs.pkg-config qemuPackage referenceQemu];
      phases = [
        {
          name = "build-live-plugin";
          script = ''
            set -eu
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-register-manifest.c} \
              -o crucible-register-manifest.so \
              $(pkg-config --libs glib-2.0)
          '';
        }
        {
          name = "run-live-manifests";
          script = ''
            set -eu
            ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=2 \
              2> x86.log
            grep -q 'CRUCIBLE_REGISTER_MANIFEST_LIVE_PASS architecture=2' x86.log

            ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=3 \
              2> aarch64.log
            grep -q 'CRUCIBLE_REGISTER_MANIFEST_LIVE_PASS architecture=3' aarch64.log

            if ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=2 \
              > reference.log 2>&1; then
              echo "unpatched QEMU unexpectedly loaded the register manifest plugin" >&2
              exit 1
            fi
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo task_ids=T-QEMU-0051
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo live_x86_64_manifest=true
              echo live_aarch64_manifest=true
            } > "$out/result"
          '';
        }
      ];
    }
