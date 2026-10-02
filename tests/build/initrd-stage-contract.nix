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
  initrdClosure = (lib.build.closureInfo {inherit pkgs;}) {
    rootPaths = [initrd];
    pname = "aos-initrd-retained-closure";
  };
  assembly = system.config.system.build.unsignedImageAssembly;
  rootPaths = map builtins.toString system.config.aos.boot.initrd.packageRoots;
  runtimeRoots = system.config.aos.boot.initrd.runtimeRoots;
  earlyFiles = lib.filterAttrs (_: entry: entry.kind == "text") system.config.aos.manager.selected.configuration.filesystemEntries;
  imageContent = system.config.system.build.etcBasedir;
  imageMetadata = system.config.system.build.etcDump;
in
  assert assembly != null;
  assert builtins.length (builtins.filter (path: path == builtins.toString pkgs.coreutils) rootPaths) == 1;
  assert builtins.length (builtins.filter (path: path == builtins.toString pkgs.coreutils) runtimeRoots) == 1;
  assert !(builtins.elem (builtins.toString pkgs.linux) runtimeRoots);
  assert !(builtins.elem (builtins.toString pkgs.aos) runtimeRoots);
  assert builtins.all (path: let
    entry = system.config.environment.etc.${path};
    expected = earlyFiles.${path};
  in
    entry.text == expected.text && entry.mode == expected.mode && entry.uid == 0 && entry.gid == 0)
  (builtins.attrNames earlyFiles);
    pkgs.mkDerivation {
      pname = "aos-initrd-native-contract-check";
      version = "1";
      src = null;
      buildDeps = [assembly imageContent imageMetadata initrdClosure pkgs.aos.testSupport pkgs.coreutils pkgs.diffutils pkgs.gawk pkgs.jq pkgs.libarchive pkgs.erofs-utils pkgs.python3 pkgs.zstd];
      outputChecks.out = {};
      exportReferencesGraph.initrd = [initrd];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            # Verify positive retention as well as refusal of incidental
            # catalog references: an allowlist alone cannot detect omissions.
            ${pkgs.jq}/bin/jq -r --arg root ${lib.escapeShellArg (builtins.toString initrd)} '
              .initrd[] | select(.path == $root) | .references[]
            ' "$NIX_ATTRS_JSON_FILE" | sort -u > actual-references
            sort -u ${initrd}/reference-roots > expected-references
            ${pkgs.diffutils}/bin/cmp expected-references actual-references

            archive_path=$(dirname "$(readlink -f ${initrd}/initrd.img)")
            ${pkgs.jq}/bin/jq -e --arg archive "$archive_path" '
              [.initrd[] | select(.path == $archive)] as $archives
              | ($archives | length) == 1 and $archives[0].references == []
            ' "$NIX_ATTRS_JSON_FILE" >/dev/null
            ${pkgs.gawk}/bin/awk -v forbidden=${lib.escapeShellArg (builtins.toString pkgs.glibc.dev)} '
              $0 == forbidden { exit 1 }
            ' ${initrdClosure}/store-paths

            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-contract ${assembly} initrd-native-contract-check
            mkdir initrd-tree root-tree
            ${pkgs.zstd}/bin/zstd -dc < ${initrd}/initrd.img > initrd.cpio
            # Resolve cpio's deferred hardlinks before extraction so directory
            # permissions are restored after every child, even across directories.
            ${pkgs.libarchive}/bin/bsdtar --format=pax -cf initrd.tar @initrd.cpio
            ${pkgs.libarchive}/bin/bsdtar -xpf initrd.tar -C initrd-tree
            ${pkgs.erofs-utils}/bin/fsck.erofs --extract=root-tree ${assembly}/inputs/root.img
            # Early services must find their canonical file prerequisites in
            # the shipped content and metadata before native activation starts.
            ${lib.concatStringsSep "\n" (lib.mapAttrsToList (path: entry: ''
                ${pkgs.diffutils}/bin/cmp \
                  ${lib.escapeShellArg "root-tree/usr/lib/aos/nix/store/${baseNameOf (builtins.toString imageContent)}/${path}"} \
                  ${lib.escapeShellArg system.config.environment.etc.${path}.source}
                ${pkgs.gawk}/bin/awk \
                  -v path=${lib.escapeShellArg "/${path}"} \
                  -v mode=${lib.escapeShellArg ("10" + (lib.optionalString (builtins.stringLength entry.mode == 3) "0") + entry.mode)} \
                  '$1 == path { found = 1; if ($3 != mode || $5 != 0 || $6 != 0) exit 1 }
                   END { if (!found) exit 1 }' ${imageMetadata}
              '')
              earlyFiles)}
            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-attachments ${assembly} initrd-native-contract-check \
              initrd-tree root-tree
            ${pkgs.python3}/bin/python3 ${./_initrd-native-contract.py} \
              ${assembly} ${initrd}/initrd-stage-contract.json initrd-tree root-tree \
              ${lib.escapeShellArg (builtins.toString pkgs.aos.packageRuntime)} \
              ${system.config.system.build.bootMetadataBinding}/binding.json \
              ${lib.escapeShellArg (builtins.toString pkgs.linux)} \
              ${lib.escapeShellArg (builtins.toString pkgs.aos)} \
              ${lib.escapeShellArg (builtins.toString pkgs.qemu)}
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
