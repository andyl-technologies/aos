# A source-co-retained check, never a distributable patched emulator root.
{pkgs}: let
  unitProfile = pkgs.callPackage ../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-clock-unit-qualification";
    enablePlugins = true;
    applyCruciblePatch = true;
    enableLinuxUser = false;
    testOnlyNonDistributable = true;
    clockAdapterUnitTestsOnly = true;
  };
  sourcePackage = pkgs.callPackage ../../pkgs/emulation/qemu-crucible-source.nix {
    qemu-crucible = unitProfile;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-cross-target-clock-units";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep unitProfile];
    runtimeDeps = [sourcePackage];

    phases = [
      {
        name = "retain-clock-unit-qualification";
        script = ''
          set -eu
          source_root=${sourcePackage}/share/aos/qemu-crucible-source
          grep -Fxq 'qemu_build_id=${unitProfile.passthru.qemuBuildIdentity}' \
            "$source_root/SOURCE-MANIFEST.env"
          grep -Fxq 'qemu_configure_flags_hash=${unitProfile.passthru.qemuConfigureFlagsHash}' \
            "$source_root/SOURCE-MANIFEST.env"
          mkdir -p "$out"
          cp -R ${unitProfile}/share/aos/crucible/. "$out/"
          printf '%s\n' 'corresponding_source=${sourcePackage}' \
            'rebuild_check=checks.crucible.phase2.qemuCrossTargetClockUnits' \
            > "$out/corresponding-source.env"
        '';
      }
    ];
  }
