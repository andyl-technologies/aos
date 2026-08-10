{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackageInventory",
  taskIds ? ["T-PKG-1"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  pkgsDefault = builtins.readFile ../../pkgs/default.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginNix = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  linuxCrucibleNix = builtins.readFile ../../pkgs/kernel/linux-crucible.nix;
  crucibleNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  fixturesNix = builtins.readFile ../../pkgs/tools/crucible-fixtures.nix;
  guestNix = builtins.readFile ../../pkgs/tools/crucible-guest.nix;
  fleetStoreNix = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  patchSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  packageFiles = [
    {
      label = "pkgs/emulation/qemu.nix";
      content = qemuNix;
      builder = "mkDerivation";
      pname = "pname ? \"qemu\"";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
    {
      label = "pkgs/emulation/crucible-qemu-plugin.nix";
      content = pluginNix;
      builder = "mkCargoPackage";
      pname = "pname = \"crucible-qemu-plugin\";";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
    {
      label = "pkgs/kernel/linux-crucible.nix";
      content = linuxCrucibleNix;
      builder = "linuxWith";
      pname = "pname = \"linux-crucible\";";
      needsBuildDeps = false;
      needsRuntimeDeps = false;
    }
    {
      label = "pkgs/tools/crucible/crucible.nix";
      content = crucibleNix;
      builder = "mkCargoPackage";
      pname = "pname = \"crucible\";";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
    {
      label = "pkgs/tools/crucible-fixtures.nix";
      content = fixturesNix;
      builder = "mkDerivation";
      pname = "pname = \"crucible-fixtures\";";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
    {
      label = "pkgs/tools/crucible-guest.nix";
      content = guestNix;
      builder = "mkCargoPackage";
      pname = "pname = \"crucible-guest\";";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
    {
      label = "pkgs/tools/crucible-fleet-store.nix";
      content = fleetStoreNix;
      builder = "mkCargoPackage";
      pname = "pname = \"crucible-fleet-store\";";
      needsBuildDeps = true;
      needsRuntimeDeps = true;
    }
  ];

  requiredPackageAttrs = [
    {
      attr = "qemu";
      expectedName = "qemu-${patchSeries.qemuVersion}";
    }
    {
      attr = "qemu-crucible";
      expectedName = "qemu-crucible-${patchSeries.qemuVersion}";
    }
    {
      attr = "qemu-crucible-reference";
      expectedName = "qemu-crucible-reference-${patchSeries.qemuVersion}";
    }
    {
      attr = "crucible-qemu-plugin";
      expectedName = "crucible-qemu-plugin-0.1.0";
    }
    {
      attr = "linux-crucible";
      expectedName = "linux-crucible-${pkgs.linux.version}";
    }
    {
      attr = "crucible";
      expectedName = "crucible-0.1.0";
    }
    {
      attr = "crucible-fixtures";
      expectedName = "crucible-fixtures-0.1.0";
    }
    {
      attr = "crucible-guest";
      expectedName = "crucible-guest-0.1.0";
    }
    {
      attr = "crucible-fleet-store";
      expectedName = "crucible-fleet-store-0.1.0";
    }
  ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  structureFailures =
    lib.concatMap (
      package:
        failuresFor package.label package.content (
          [
            {
              label = "package builder";
              needle = package.builder;
            }
            {
              label = "package name";
              needle = package.pname;
            }
          ]
          ++ lib.optionals package.needsBuildDeps [
            {
              label = "build dependency classification";
              needle = "buildDeps =";
            }
          ]
          ++ lib.optionals package.needsRuntimeDeps [
            {
              label = "runtime dependency classification";
              needle = "runtimeDeps =";
            }
          ]
        )
        ++ forbiddenFor package.label package.content [
          {
            label = "nixpkgs import";
            needle = "<nixpkgs>";
          }
          {
            label = "hostTools pattern";
            needle = "hostTools";
          }
        ]
    )
    packageFiles;

  attrFailures =
    lib.concatMap (
      package:
        lib.optionals (!(pkgs ? ${package.attr})) [
          "pkgs/default.nix: missing package attr `${package.attr}`"
        ]
        ++ lib.optionals ((pkgs.${package.attr}.name or null) != package.expectedName) [
          "pkgs.${package.attr}: expected derivation name ${package.expectedName}, got ${pkgs.${package.attr}.name or "<missing>"}"
        ]
    )
    requiredPackageAttrs;

  qemuSourceFailures =
    lib.optionals (pkgs.qemu.version != pkgs.qemu-crucible.version) [
      "pkgs.qemu and pkgs.qemu-crucible must share the same pinned QEMU version"
    ]
    ++ lib.optionals (pkgs.qemu.passthru.series.qemuSourceHash != pkgs.qemu-crucible.passthru.series.qemuSourceHash) [
      "pkgs.qemu and pkgs.qemu-crucible must share the same pinned QEMU source hash"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=false" pkgs.qemu.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must be unpatched"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" pkgs.qemu.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must not advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=true" pkgs.qemu-crucible.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must apply the Crucible patch series"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=qemu-crucible" pkgs.qemu-crucible.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=false" pkgs.qemu-crucible-reference.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: reference QEMU must be unpatched"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" pkgs.qemu-crucible-reference.passthru.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: reference QEMU must not advertise Crucible sim capability"
    ];

  cargoSourceFailures =
    failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginNix [
      {
        label = "vendored cargo dependencies";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "inline cargo dependency hash";
        needle = "hash = \"sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=\";";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" crucibleNix [
      {
        label = "vendored cargo dependencies";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "inline cargo dependency hash";
        needle = "cargoDepsHash = \"sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=\";";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-guest.nix" guestNix [
      {
        label = "vendored cargo dependencies";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "inline cargo dependency hash";
        needle = "hash = \"sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=\";";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStoreNix [
      {
        label = "vendored cargo dependencies";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "inline cargo dependency hash";
        needle = "cargoDepsHash = \"sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=\";";
      }
    ];

  inventoryDocFailures = failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
    {
      label = "T-PKG-1 completion note";
      needle = "Completed by `checks.crucible.phase7.cruciblePackageInventory`";
    }
    {
      label = "qemu package attr note";
      needle = "`pkgs.qemu-crucible`";
    }
    {
      label = "fixtures package attr note";
      needle = "`pkgs.crucible-fixtures`";
    }
  ];

  defaultWiringFailures =
    failuresFor "tests/crucible/default.nix" (builtins.readFile ./default.nix) [
      {
        label = "phase7 inventory check imported";
        needle = "cruciblePackageInventory = import ./phase7-crucible-package-inventory.nix";
      }
    ]
    ++ failuresFor "pkgs/default.nix" pkgsDefault [
      {
        label = "package auto-discovery";
        needle = "discoverPackages ./.";
      }
      {
        label = "qemu-crucible explicit override";
        needle = "qemu-crucible = callPackage ./emulation/qemu.nix";
      }
      {
        label = "qemu-crucible reference override";
        needle = "qemu-crucible-reference = callPackage ./emulation/qemu.nix";
      }
    ];

  failures =
    structureFailures
    ++ attrFailures
    ++ qemuSourceFailures
    ++ cargoSourceFailures
    ++ inventoryDocFailures
    ++ defaultWiringFailures;
in
  if failures != []
  then throw "crucible phase7 package inventory check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-package-inventory";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
      ];

      passthru = {
        qemu = pkgs.qemu;
        qemuCrucible = pkgs.qemu-crucible;
        qemuCrucibleReference = pkgs.qemu-crucible-reference;
        plugin = pkgs.crucible-qemu-plugin;
        linuxCrucible = pkgs.linux-crucible;
        crucible = pkgs.crucible;
        fixtures = pkgs.crucible-fixtures;
        guest = pkgs.crucible-guest;
        fleetStore = pkgs.crucible-fleet-store;
      };

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            inventory=pkgs.qemu,pkgs.qemu-crucible,pkgs.qemu-crucible-reference,pkgs.crucible-qemu-plugin,pkgs.linux-crucible,pkgs.crucible,pkgs.crucible-fixtures,pkgs.crucible-guest,pkgs.crucible-fleet-store
            emulation_packages=pkgs.qemu,pkgs.qemu-crucible,pkgs.qemu-crucible-reference,pkgs.crucible-qemu-plugin
            kernel_packages=pkgs.linux-crucible
            tool_packages=pkgs.crucible,pkgs.crucible-fixtures,pkgs.crucible-guest,pkgs.crucible-fleet-store
            qemu_version=${patchSeries.qemuVersion}
            qemu_source_hash=${patchSeries.qemuSourceHash}
            production_qemu_patches_applied=false
            production_qemu_sim_capability=none
            patched_qemu_patches_applied=true
            patched_qemu_sim_capability=qemu-crucible
            reference_qemu_patches_applied=false
            reference_qemu_sim_capability=none
            cargo_deps=fetchCargoDeps
            package_structure_checked=true
            dependency_classification_checked=true
            nixpkgs_dependency=false
            host_tools_pattern=false
            RESULT
          '';
        }
      ];
    }
