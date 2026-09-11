##! Qualifies exact image formats and their shared bootable disk on the build host.
{
  pkgs,
  lib,
}: {
  systems,
  sourceIdentity,
}: let
  buildPackages = pkgs.buildPackages;
  platform = pkgs.stdenv.hostPlatform.system;
  buildPlatform = buildPackages.stdenv.hostPlatform.system;
  isX86 = platform == "x86_64-linux";
  formats = ["qcow2" "raw" "vhd" "vmdk"];
  systemNames = builtins.attrNames systems;

  # Firmware is target data. Every executable launched by the harness is native.
  firmwareCode = "${pkgs.edk2}/FV/${
    if isX86
    then "OVMF"
    else "AAVMF"
  }_CODE.fd";
  firmwareVars =
    if isX86
    then "${pkgs.edk2}/FV/OVMF_VARS.fd"
    else "";
  tools = {
    qemu = "${buildPackages.qemu}/bin/qemu-system-${
      if isX86
      then "x86_64"
      else "aarch64"
    }";
    qemuImg = "${buildPackages.qemu}/bin/qemu-img";
    zstd = "${buildPackages.zstd}/bin/zstd";
    ssh = "${buildPackages.openssh}/bin/ssh";
    scp = "${buildPackages.openssh}/bin/scp";
    sshKeygen = "${buildPackages.openssh}/bin/ssh-keygen";
    swtpm = "${buildPackages.swtpm}/bin/swtpm";
    sgdisk = "${buildPackages.gptfdisk}/sbin/sgdisk";
    objcopy = "${buildPackages.binutils}/bin/objcopy";
  };
  runnerFiles = {
    "image_matrix.py" = ./image_matrix.py;
    "image_matrix_boot.py" = ./image_matrix_boot.py;
    "qualification_image.py" = ./qualification-image.py;
  };
  installRunner = lib.concatStringsSep "\n" (lib.mapAttrsToList (name: path: ''
      cp ${path} "$TMPDIR/image-matrix/${name}"
    '')
    runnerFiles);
  nativeTools = [
    buildPackages.coreutils
    buildPackages.python3
    buildPackages.qemu
    buildPackages.zstd
    buildPackages.openssh
    buildPackages.swtpm
    buildPackages.gptfdisk
    buildPackages.binutils
  ];

  subject = name: let
    system = systems.${name};
    config = system.config;
    secureBoot = config.aos.boot.secureBoot;
  in {
    inherit name;
    images = builtins.mapAttrs (_: image: toString image) system.build.image;
    expected = {
      toplevel = toString system.build.toplevel;
      version = config.aos.system.version;
      kernel = system.build.kernel.version;
      moduleAbi = config.aos.system.moduleAbi;
      role =
        if config.aos.roles.edge.enable
        then "edge"
        else if config.aos.roles.server.enable
        then "server"
        else null;
      security = {
        rootFilesystem = config.aos.filesystems.rootFsType;
        readOnlyRoot = config.aos.filesystems.rootReadOnly;
        verity = config.aos.security.verity.enable;
        secureBoot = secureBoot.enable;
        measuredBoot = secureBoot.measuredBoot.enable;
        lockdown =
          if secureBoot.lockdown.enable
          then secureBoot.lockdown.mode
          else "none";
      };
    };
    guestTools = {
      apm = "${pkgs.aos.apm}/bin/apm";
      enroll =
        if secureBoot.enable
        then "${config.aos.config.artifacts.secure-boot-enroll}/bin/aos-sb-enroll"
        else null;
      enrollAuthDir =
        if secureBoot.enable
        then toString secureBoot._effectiveEnrollAuthDir
        else null;
    };
  };
  inventory = {
    schema = "aos.image-matrix-input/v1";
    inherit platform buildPlatform sourceIdentity formats tools firmwareCode firmwareVars;
    systems = map subject systemNames;
  };
  manifest = value: let
    file = buildPackages.writeTextFile {
      name = "aos-image-matrix-input";
      destination = "/manifest.json";
      text = builtins.toJSON value;
    };
  in "${file}/manifest.json";

  runner = buildPackages.mkDerivation {
    pname = "aos-image-matrix-runner-check";
    version = "1";
    src = null;
    buildDeps = [buildPackages.coreutils buildPackages.python3];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$TMPDIR/image-matrix" "$out"
          cp ${./image_matrix.py} "$TMPDIR/image-matrix/image_matrix.py"
          cp ${./image_matrix_boot.py} "$TMPDIR/image-matrix/image_matrix_boot.py"
          cp ${./test_image_matrix.py} "$TMPDIR/image-matrix/test_image_matrix.py"
          cp ${./qualification-image.py} "$TMPDIR/image-matrix/qualification-image.py"
          cp ${./test_qualification_image.py} "$TMPDIR/image-matrix/test_qualification_image.py"
          cd "$TMPDIR/image-matrix"
          PYTHONDONTWRITEBYTECODE=1 ${buildPackages.python3}/bin/python3 -m unittest -v test_image_matrix test_qualification_image
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  };
  checks = builtins.listToAttrs (map (name: {
      inherit name;
      value = buildPackages.mkDerivation {
        pname = "aos-image-matrix-${name}-${platform}";
        version = "1";
        src = null;
        buildDeps = nativeTools;
        requiredSystemFeatures = lib.optionals isX86 ["kvm"];
        outputChecks.out = {};
        dontStrip = true;
        dontNukeRefs = true;
        phases = [
          {
            name = "qualify";
            script = ''
              mkdir -p "$TMPDIR/image-matrix" "$out"
              ${installRunner}
              cd "$TMPDIR/image-matrix"
              unset LD_LIBRARY_PATH
              PYTHONDONTWRITEBYTECODE=1 ${buildPackages.python3}/bin/python3 image_matrix.py run \
                --manifest ${manifest (inventory // {systems = [(subject name)];})} \
                --output "$out/report.json"
            '';
          }
        ];
      };
    })
    systemNames);
in
  assert builtins.elem platform ["x86_64-linux" "aarch64-linux"];
  assert buildPlatform == "x86_64-linux";
  assert systemNames != [];
  assert builtins.all (name: builtins.attrNames systems.${name}.build.image == formats) systemNames; {
    inherit inventory runner;
    systems = checks;
    all = buildPackages.mkDerivation {
      pname = "aos-image-matrix-${platform}";
      version = "1";
      src = null;
      buildDeps = [buildPackages.coreutils buildPackages.python3 runner] ++ builtins.attrValues checks;
      outputChecks.out = {};
      dontStrip = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "aggregate";
          script = ''
            mkdir -p "$out"
            PYTHONDONTWRITEBYTECODE=1 ${buildPackages.python3}/bin/python3 ${./image_matrix.py} merge \
              --manifest ${manifest inventory} \
              --output "$out/report.json" \
              ${lib.concatStringsSep " \\\n            " (map (name: "${checks.${name}}/report.json") systemNames)}
          '';
        }
      ];
    };
  }
