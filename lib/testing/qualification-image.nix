##! Exercises a published image set and its retained predecessor in QEMU.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  checks,
  packageChecks,
  assessmentRoot ? "/etc/aos-release/qualification-assessments",
  stagingHubUrl ? "https://aos.staging.andyl.org",
  scenarioSource ? ./qualification-image.py,
  scenarioModules ? {},
}: let
  # Firmware belongs to the guest; every executed tool belongs to the build host.
  native = pkgs.buildPackages;
  platform = pkgs.stdenv.hostPlatform.system;
  isX86 = platform == "x86_64-linux";
  isAarch64 = platform == "aarch64-linux";
  qemu =
    if isX86
    then "${native.qemu}/bin/qemu-system-x86_64"
    else "${native.qemu}/bin/qemu-system-aarch64";
  firmwareCode =
    if isX86
    then "${pkgs.edk2}/FV/OVMF_CODE.fd"
    else "${pkgs.edk2}/FV/AAVMF_CODE.fd";
  firmwareVars =
    if isX86
    then "${pkgs.edk2}/FV/OVMF_VARS.fd"
    else "";
  runtimePath = lib.makeBinPath [
    native.bash
    native.coreutils
    native.diffutils
    native.e2fsprogs
    native.findutils
    native.gawk
    native.grep
    native.sed
    native.gptfdisk
    native.jq
    native.openssh
    native.openssl
    native.qemu
    native.swtpm
    native.tar
    native.zstd
    native.nix
  ];
  scenario = native.writeTextFile {
    name = "${name}-scenario.py";
    destination = "/share/aos-release/qualification-image.py";
    text = builtins.readFile scenarioSource;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-image-pycache \
        ${native.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-image.py
    '';
  };
  modules = lib.mapAttrsToList (moduleName: source:
    assert builtins.match "[A-Za-z_][A-Za-z0-9_]*" moduleName != null;
      native.writeTextFile {
        name = "${name}-${moduleName}.py";
        destination = "/share/aos-release/${moduleName}.py";
        text = builtins.readFile source;
        checkPhase = ''
          PYTHONPYCACHEPREFIX=$TMPDIR/qualification-module-pycache \
            ${native.python3}/bin/python3 -m py_compile \
            $out/share/aos-release/${moduleName}.py
        '';
      })
  scenarioModules;
  modulePath = lib.concatStringsSep ":" (map (module: "${module}/share/aos-release") modules);
in
  assert identity != "";
  assert isX86 || isAarch64;
  assert builtins.substring 0 1 assessmentRoot == "/";
  assert builtins.match "https://[^/]+/?" stagingHubUrl != null;
    native.writeShellScriptBin name ''
      set -euo pipefail

      export PATH=${lib.escapeShellArg runtimePath}
      export HOME=$PWD/home
      export TMPDIR=$PWD/tmp
      export LC_ALL=C
      export PYTHONPATH=${lib.escapeShellArg modulePath}
      export AOS_QUALIFICATION_PLATFORM=${lib.escapeShellArg platform}
      export AOS_QUALIFICATION_IDENTITY=${lib.escapeShellArg identity}
      export AOS_QUALIFICATION_CHECKS=${lib.escapeShellArg (builtins.toJSON checks)}
      export AOS_QUALIFICATION_PACKAGE_CHECKS=${lib.escapeShellArg (builtins.toJSON packageChecks)}
      export AOS_QUALIFICATION_ASSESSMENTS=${lib.escapeShellArg assessmentRoot}
      export AOS_QUALIFICATION_STAGING_HUB_URL=${lib.escapeShellArg stagingHubUrl}
      export AOS_QUALIFICATION_QEMU=${lib.escapeShellArg qemu}
      export AOS_QUALIFICATION_QEMU_IMG=${lib.escapeShellArg "${native.qemu}/bin/qemu-img"}
      export AOS_QUALIFICATION_FIRMWARE_CODE=${lib.escapeShellArg firmwareCode}
      export AOS_QUALIFICATION_FIRMWARE_VARS=${lib.escapeShellArg firmwareVars}
      export AOS_QUALIFICATION_SWTPM=${lib.escapeShellArg "${native.swtpm}/bin/swtpm"}
      export AOS_QUALIFICATION_SGDISK=${lib.escapeShellArg "${native.gptfdisk}/sbin/sgdisk"}
      export AOS_QUALIFICATION_MKE2FS=${lib.escapeShellArg "${native.e2fsprogs}/sbin/mke2fs"}
      export AOS_QUALIFICATION_ZSTD=${lib.escapeShellArg "${native.zstd}/bin/zstd"}
      export AOS_QUALIFICATION_SSH=${lib.escapeShellArg "${native.openssh}/bin/ssh"}
      export AOS_QUALIFICATION_SCP=${lib.escapeShellArg "${native.openssh}/bin/scp"}
      export AOS_QUALIFICATION_SSH_KEYGEN=${lib.escapeShellArg "${native.openssh}/bin/ssh-keygen"}
      export AOS_QUALIFICATION_OPENSSL=${lib.escapeShellArg "${native.openssl}/bin/openssl"}
      export AOS_QUALIFICATION_OBJCOPY=${lib.escapeShellArg "${native.binutils}/bin/objcopy"}
      export AOS_QUALIFICATION_NIX_STORE=${lib.escapeShellArg "${native.nix}/bin/nix-store"}

      umask 077
      mkdir -p "$HOME" "$TMPDIR"

      # The coordinator retained this same canonical request beside the
      # downloaded objects. Drain stdin so its bounded writer always exits.
      cat >/dev/null

      ${native.python3}/bin/python3 \
        ${scenario}/share/aos-release/qualification-image.py

      exec ${native.aos}/bin/aos release qualification respond \
        --request request.json \
        --scenarios scenario-registry.json \
        --report scenario-report.json \
        --identity ${lib.escapeShellArg identity}
    ''
