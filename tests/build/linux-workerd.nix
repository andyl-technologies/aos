##! Executes the reviewed Workerd operations inside AArch64 Linux.
##!
##! Both public package identities use their built output closures. The guest
##! runs the same HTTP and malformed-configuration probes as release
##! qualification; this build check does not assert staged-artifact admission.
{pkgs}: let
  cross = import ../.. {
    system = pkgs.stdenv.buildPlatform.system;
    crossSystem = "aarch64-linux";
  };
  target = cross.pkgs;
  packageNames = ["workerd" "workerd-source"];
  probes = import ../../qualification/package-probes/q-z-fifth-command-tools.nix {
    testing.mkQualificationPackageProbe = args: args.spec;
  };
  probeSpecs = pkgs.writeTextFile {
    name = "linux-workerd-probes";
    destination = "/specs.json";
    text = builtins.toJSON (builtins.listToAttrs (map (name: {
        inherit name;
        value = probes.${name};
      })
      packageNames));
  };
  probeRunner = pkgs.writeTextFile {
    name = "linux-workerd-probe-runner";
    destination = "/probe.py";
    text = builtins.readFile ../../lib/testing/qualification-package-probe.py;
  };
  mkClosureInfo = import ../../lib/build/closure-info.nix {
    inherit pkgs;
    lib = cross.lib;
  };
  packageClosures = builtins.listToAttrs (map (name: {
      inherit name;
      value = mkClosureInfo {rootPaths = [target.${name}];};
    })
    packageNames);
  scenario = pkgs.writeTextFile {
    name = "linux-workerd-scenario";
    destination = "/scenario.py";
    text = ''
      import json
      import os
      import pathlib
      import subprocess

      assert os.uname().machine == "aarch64", os.uname()
      specs = json.loads(pathlib.Path("${probeSpecs}/specs.json").read_text())
      closure_files = ${builtins.toJSON (builtins.mapAttrs (_: value: "${value}/store-paths") packageClosures)}
      packages = ${builtins.toJSON (builtins.listToAttrs (map (name: {
          inherit name;
          value = target.${name}.outPath;
        })
        packageNames))}

      for name, output in packages.items():
          closure = pathlib.Path(closure_files[name]).read_text().splitlines()
          work = pathlib.Path("/tmp") / name
          work.mkdir()
          spec = work / "spec.json"
          spec.write_text(json.dumps(specs[name]))
          report = work / "report.json"
          environment = os.environ.copy()
          environment.update({
              "PATH": "",
              "AOS_QUALIFICATION_PACKAGE": name,
              "AOS_QUALIFICATION_PLATFORM": "aarch64-linux",
              "AOS_QUALIFICATION_PACKAGE_OUTPUTS": json.dumps({"out": output}),
              "AOS_QUALIFICATION_PACKAGE_CLOSURE": json.dumps(closure),
              "AOS_QUALIFICATION_PACKAGE_PROFILE": str(work / "profile"),
              "AOS_QUALIFICATION_PROBE_WORK": str(work),
              "AOS_QUALIFICATION_PROBE_REPORT": str(report),
              "AOS_QUALIFICATION_PYTHON": "${target.python3}/bin/python3",
              "AOS_QUALIFICATION_BASH": "${target.bash}/bin/bash",
              "AOS_QUALIFICATION_CC": "/unavailable/cc",
              "AOS_QUALIFICATION_CXX": "/unavailable/c++",
          })
          subprocess.run(
              ["${target.python3}/bin/python3", "${probeRunner}/probe.py", str(spec)],
              env=environment,
              check=True,
          )
          result = json.loads(report.read_text())
          assert result["package"] == name, result
          assert result["platform"] == "aarch64-linux", result
          print(json.dumps(result, sort_keys=True), flush=True)
    '';
  };
  empty = target.writeTextFile {
    name = "linux-workerd-empty-system";
    text = "";
  };
  system.config.system.build = {
    toplevel = empty;
    kernel = target.linux;
    systemdSystemPresets = empty;
  };
  rootfs = import ../../lib/build/rootfs.nix {
    pkgs = cross.buildPackages;
    lib = cross.lib;
    inherit system;
    pname = "linux-workerd-rootfs";
    shrinkToFit = false;
    minSizeMiB = 2048;
    extraClosures =
      [
        target.workerd
        target.workerd-source
        target.python3
        target.bash
        target.coreutils
        target.util-linux
        target.iproute2
        scenario
        probeSpecs
        probeRunner
      ]
      ++ builtins.attrValues packageClosures;
    symlinkFarmPkgs = [];
    postPopulate = ''
      ln -s ../nix.lower/store rootfs/nix/store
      cat > rootfs/init <<'INIT'
      #!${target.bash}/bin/bash
      set -euxo pipefail
      export PATH=${target.coreutils}/bin:${target.util-linux}/bin
      export HOME=/tmp
      export TMPDIR=/tmp
      export LC_ALL=C

      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      ${target.iproute2}/sbin/ip link set lo up
      ${target.python3}/bin/python3 ${scenario}/scenario.py

      echo AOS_WORKERD_AARCH64_VM_PASS
      sync
      echo b > /proc/sysrq-trigger
      while :; do sleep 1; done
      INIT
      chmod +x rootfs/init
    '';
  };
in
  pkgs.mkDerivation {
    pname = "linux-workerd-vm";
    version = "0";
    src = null;
    buildDeps = [pkgs.qemu pkgs.coreutils pkgs.grep];
    phases = [
      {
        name = "run";
        script = ''
          cp ${rootfs}/root.img root.img
          chmod u+w root.img

          qemu_status=0
          timeout 600 qemu-system-aarch64 \
            -machine virt -cpu cortex-a72 -accel tcg -smp 4 -m 2048 \
            -kernel ${target.linux}/boot/vmlinuz-* \
            -drive file=root.img,format=raw,if=virtio \
            -append 'root=/dev/vda rw rootwait init=/init console=ttyAMA0 sysrq_always_enabled=1 panic=1' \
            -nographic -no-reboot -monitor none \
            > serial.log 2>&1 || qemu_status=$?

          tr -d '\r' < serial.log
          if ! grep -Fq AOS_WORKERD_AARCH64_VM_PASS serial.log; then
            echo "Workerd guest failed before completion (QEMU status $qemu_status)" >&2
            exit 1
          fi
          mkdir -p "$out"
          cp serial.log "$out/"
        '';
      }
    ];
  }
