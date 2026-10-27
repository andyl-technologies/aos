##! Check complete native source application without compiling a kernel.
{
  lib,
  mkDerivation,
  linuxSource,
  coreutils,
  patch,
  python3,
}: let
  fixtures = ./_crucible-q35-cold-source;
  sourcePatches = import (fixtures + "/patches.nix");
in
  mkDerivation {
    # This emits a source-application report, not a native kernel or a
    # corresponding-source release artifact. No compiler ISA is selected.
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
    pname = "linux-controller-q35-cold-source";
    version = linuxSource.version;
    buildDeps = [coreutils patch python3];
    runtimeDeps = [];
    phases = [
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -I -B ${fixtures}/check-disk.py "$PWD"
          mkdir kernel
          tar xf ${linuxSource.src} --strip-components=1 -C kernel
          ${coreutils}/bin/timeout 180 ${python3}/bin/python3 -I -B \
            ${fixtures}/apply-kernel-source.py "$PWD/kernel" ${patch}/bin/patch \
            ${lib.concatMapStringsSep " " (sourcePatch: lib.escapeShellArg "${sourcePatch}") sourcePatches}
          mkdir -p $out
          cp ${fixtures}/LICENSES.md $out/LICENSES.md
          cp ${fixtures}/complete-source-catalog.json $out/complete-source-catalog.json
          cat > $out/report <<'REPORT'
          complete ordered native source chain: exact preimages and postimages
          patch application: zero fuzz and no offsets
          cap43/45 availability and selected RUN: unsupported
          kernel compilation/link, device timers, native QEMU, nested guest,
          physical quantum stop, output publication and Ready: unqualified
          REPORT
        '';
      }
    ];
  }
