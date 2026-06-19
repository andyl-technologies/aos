{
  pkgs,
  lib,
}: let
  requiredAttrs = [
    "crucible"
    "crucible-qemu-plugin"
    "qemu-crucible"
  ];

  attrFailures =
    lib.concatMap (
      attr:
        lib.optionals (!(builtins.hasAttr attr pkgs)) [
          "pkgs.${attr} is not exposed by the AOS package set"
        ]
    )
    requiredAttrs;

  packages =
    if attrFailures == []
    then {
      inherit (pkgs) crucible crucible-qemu-plugin qemu-crucible;
    }
    else {};
in
  if attrFailures != []
  then throw "crucible phase1 AOS workspace build lint failed:\n${builtins.concatStringsSep "\n" attrFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-aos-workspace-build";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        packages.crucible
        packages.crucible-qemu-plugin
        packages.qemu-crucible
      ];

      phases = [
        {
          name = "check";
          script = ''
            set -eu

            test -x ${packages.crucible}/bin/crucible
            test -f ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^build_system=mkCargoPackage$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^cargo_deps=fetchCargoDeps$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q -- '-p crucible-qemu-plugin' \
              ${packages.crucible}/nix-support/crucible-build-info

            test -f ${packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
            test -f ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^build_system=mkCargoPackage$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^cargo_deps=fetchCargoDeps$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_package=qemu-crucible$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_plugin_header=${packages.qemu-crucible}/include/qemu/qemu-plugin.h$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info

            test -f ${packages.qemu-crucible}/include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_crucible_rr_switch_quantum' \
              ${packages.qemu-crucible}/include/qemu/qemu-plugin.h

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.aosWorkspaceBuild
            tasks=T-CRATE-14
            packages=crucible,crucible-qemu-plugin,qemu-crucible
            cargo_deps=fetchCargoDeps
            plugin_headers=qemu-crucible
            RESULT
          '';
        }
      ];
    }
