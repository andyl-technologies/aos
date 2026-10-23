##! Binds exact source-built commands embedded in boot preparation artifacts.
{
  pkgs,
  lib,
}: let
  packageRuntime = pkgs.aos.packageRuntime;
  configurationBoot = pkgs.aos-configuration-lower;
  tools = [
    pkgs.bash
    pkgs.coreutils
    pkgs.nix
    pkgs.erofs-utils
    pkgs.util-linux
    packageRuntime
    configurationBoot
  ];
  configurationEnvironment = {
    AOS_MKFS_EROFS = "${pkgs.erofs-utils}/bin/mkfs.erofs";
    AOS_FSCK_EROFS = "${pkgs.erofs-utils}/bin/fsck.erofs";
    AOS_MOUNT = "${pkgs.util-linux}/bin/mount";
    AOS_UMOUNT = "${pkgs.util-linux}/bin/umount";
    AOS_PACKAGE_RUNTIME = "${packageRuntime}/bin/aos-package-runtime";
  };
  standaloneEnvironment = {
    AOS_PACKAGE_RUNTIME = "${packageRuntime}/bin/aos-package-runtime";
    AOS_BOOT_CONFIGURATION = "${packageRuntime}/bin/aos-boot-configuration";
    AOS_CONFIGURATION_BOOT = "${configurationBoot}/bin/aos-configuration-boot";
  };
  environmentFile = values:
    lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name}=${value}") values);
in
  pkgs.mkDerivation {
    pname = "aos-bazel-boot-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.jq];
    outputChecks.out = {};
    exportReferencesGraph.tools = tools;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          jq -cS '{schema: 1, closure: [.tools[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
          cat > "$out/configuration.env" <<'ENVIRONMENT'
          ${environmentFile configurationEnvironment}
          ENVIRONMENT
          cat > "$out/standalone.env" <<'ENVIRONMENT'
          ${environmentFile standaloneEnvironment}
          ENVIRONMENT
          cat > "$out/test-setup" <<'SETUP'
          #!${pkgs.bash}/bin/bash
          set -euo pipefail
          export PATH=${lib.escapeShellArg (lib.concatStringsSep ":" (map (tool: "${tool}/bin") [pkgs.bash pkgs.coreutils pkgs.nix]))}
          export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
          export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate
          exec "$@"
          SETUP
          chmod +x "$out/test-setup"
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files([
              "configuration.env",
              "standalone.env",
              "test-setup",
              "closure.json",
          ], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
