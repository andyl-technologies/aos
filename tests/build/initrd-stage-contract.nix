##! Qualifies real archives and their exact native deployment attachments.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixtureAuthorities = {pkgs, ...}: {
    aos.profiles.canonicalRelease = {
      enable = true;
      publicAuthorities = {
        secureBootCertificate = "${pkgs.secure-boot-test-keys}/db.crt";
        moduleSigningCertificate = "${pkgs.secure-boot-test-keys}/modsign.crt";
        pcrPolicyKey = "${pkgs.secure-boot-test-keys}/pcr.pem";
        firmwareEnrollment = "${pkgs.secure-boot-test-keys}";
      };
    };
    aos.boot.initrd.packageRoots = [pkgs.coreutils pkgs.coreutils];
    aos.boot.initrd.nonPackageRuntimeArtifacts = [
      (builtins.toString pkgs.coreutils)
      (builtins.toString pkgs.coreutils)
    ];
  };
  system = mkSystem {modules = [../../systems/server.nix fixtureAuthorities];};
  initrd = system.config.system.build.initrd;
  assembly = system.config.system.build.unsignedImageAssembly;
  rootPaths = map builtins.toString system.config.aos.boot.initrd.packageRoots;
  runtimeRoots = system.config.aos.boot.initrd.runtimeRoots;
in
  assert assembly != null;
  assert builtins.length (builtins.filter (path: path == builtins.toString pkgs.coreutils) rootPaths) == 1;
  assert builtins.length (builtins.filter (path: path == builtins.toString pkgs.coreutils) runtimeRoots) == 1;
  assert !(builtins.elem (builtins.toString pkgs.linux) runtimeRoots);
  assert !(builtins.elem (builtins.toString pkgs.aos) runtimeRoots);
    pkgs.mkDerivation {
      pname = "aos-initrd-native-contract-check";
      version = "1";
      src = null;
      buildDeps = [assembly pkgs.aos.testSupport pkgs.coreutils pkgs.libarchive pkgs.erofs-utils pkgs.python3 pkgs.zstd];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-contract ${assembly} initrd-native-contract-check
            mkdir initrd-tree root-tree
            ${pkgs.zstd}/bin/zstd -dc ${initrd}/initrd.img > initrd.cpio
            # Resolve cpio's deferred hardlinks before extraction so directory
            # permissions are restored after every child, even across directories.
            ${pkgs.libarchive}/bin/bsdtar --format=pax -cf initrd.tar @initrd.cpio
            ${pkgs.libarchive}/bin/bsdtar -xpf initrd.tar -C initrd-tree
            ${pkgs.erofs-utils}/bin/fsck.erofs --extract=root-tree ${assembly}/inputs/root.img
            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-attachments ${assembly} initrd-native-contract-check \
              initrd-tree root-tree
            ${pkgs.python3}/bin/python3 ${./_initrd-native-contract.py} \
              ${assembly} ${initrd}/initrd-stage-contract.json initrd-tree root-tree \
              ${lib.escapeShellArg (builtins.toString pkgs.aos.packageRuntime)} \
              ${lib.escapeShellArg (builtins.toString pkgs.linux)} \
              ${lib.escapeShellArg (builtins.toString pkgs.aos)} \
              ${lib.escapeShellArg (builtins.toString pkgs.qemu)}
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
