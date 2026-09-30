##! Bounded native evaluation checks grouped by established CI target names.
{
  pkgs,
  lib,
  system,
  mkSystem,
  mkDeployableSystem,
}: let
  verify = name: value:
    if builtins.isAttrs value
    then builtins.all (key: verify "${name}.${key}" value.${key}) (builtins.attrNames value)
    else if builtins.isList value
    then builtins.all (item: verify name item) value
    else if value == true
    then true
    else throw "native evaluation check failed: ${name}";
  fixture = path: let
    imported =
      if path == ../../tests/effects/packages.nix
      then (import path).checks
      else import path;
  in
    if builtins.isFunction imported
    then imported (builtins.intersectAttrs (builtins.functionArgs imported) {inherit lib pkgs;})
    else imported;
  check = name: paths:
    assert builtins.all (path: verify "${name}.${builtins.baseNameOf path}" (fixture path)) paths;
      pkgs.mkDerivation {
        pname = "aos-eval-${name}";
        version = "0";
        src = null;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p "$out"
              echo PASS > "$out/result"
            '';
          }
        ];
      };
in {
  # Image assembly, ELF and rendered unit validation have their own artifact
  # checks. These fixtures exercise the actual authored policy and native stage
  # composition without repeatedly resolving entire server/edge images.
  rendered-system = check "rendered-system" [
    ../../tests/effects/build-invariants.nix
    ../../tests/effects/stages.nix
    ../../tests/effects/boot-consumers.nix
    ../../tests/effects/systemd-resources.nix
    ../../tests/effects/configuration-policy.nix
  ];

  # Preserve the public target name while checking source/library contracts.
  # The native library derives its schema from declarations, with no ABI counter.
  module-abi = check "module-library" [
    ../../tests/effects/packages.nix
    ../../tests/effects/types.nix
    ../../tests/effects/frozen-handler.nix
    ../../tests/effects/platform-replay.nix
  ];

  runtime-roles = check "runtime-roles" [
    ../../tests/effects/runtime-roles.nix
    ../../tests/effects/daemon-consumers.nix
    ../../tests/effects/security-services.nix
    ../../tests/effects/release-maintenance.nix
    ../../tests/effects/runtime-checks.nix
  ];

  registry-policy = check "registry-policy" [../../tests/effects/configuration-policy.nix];

  storage-profile = check "storage-profile" [
    ../../tests/effects/storage-profile.nix
    ../../tests/abilities/block-storage.nix
    ../../tests/abilities/base-filesystems-native.nix
    ../../tests/effects/boot-consumers.nix
  ];
}
