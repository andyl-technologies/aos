# lib/testing/config-manifest.nix — shared Rust/Nix manifest contract.
{
  pkgs,
  lib,
  system,
}: let
  fixture = builtins.fromJSON (builtins.readFile ../../crates/aos-package/tests/fixtures/config_manifest/manifest.json);
  actual = system.config.system.build.configManifest;
  inputNames = value:
    builtins.attrNames value.inputs
    == [
      "base_lib"
      "config_modules"
      "evaluator"
      "host_nix"
      "instance_facts"
    ];
  ownershipNames = value:
    builtins.attrNames value.ownership
    == [
      "etc"
      "jobScripts"
      "presets"
      "storePaths"
      "units"
      "users"
    ];
  validShape = value:
    value.schema
    == "aos.config-manifest/v1"
    && builtins.isAttrs value.etc
    && builtins.isAttrs value.units
    && builtins.isAttrs value.jobScripts
    && builtins.isList value.users
    && builtins.isList value.presets
    && builtins.isList value.storePaths
    && builtins.isList value.packages
    && builtins.isAttrs value.packageOutputs
    && builtins.isAttrs value.graph.edges
    && builtins.isAttrs value.config
    && builtins.isAttrs value.credentials
    && builtins.isInt value.module_abi
    && inputNames value
    && ownershipNames value;
  exactOwnershipCoverage = value:
    builtins.attrNames value.etc
    == builtins.attrNames value.ownership.etc
    && builtins.attrNames value.units == builtins.attrNames value.ownership.units
    && builtins.attrNames value.jobScripts == builtins.attrNames value.ownership.jobScripts
    && builtins.sort (a: b: a < b) (builtins.map (user: user.name) value.users)
    == builtins.attrNames value.ownership.users
    && builtins.sort (a: b: a < b) (builtins.map (preset: "${preset.unit}:${preset.source}") value.presets)
    == builtins.attrNames value.ownership.presets
    && value.storePaths == builtins.attrNames value.ownership.storePaths;
  validInputs = value:
    value.module_abi
    == value.inputs.base_lib.module_abi
    && value.inputs.config_modules.count == builtins.length value.inputs.config_modules.store_paths
    && value.inputs.config_modules.count == builtins.length value.inputs.config_modules.nar_hashes
    && value.inputs.config_modules.count == builtins.length value.inputs.config_modules.package_names
    && value.inputs.config_modules.count == builtins.length value.inputs.config_modules.module_abi_compat
    && builtins.match "/nix/store/.*" value.inputs.base_lib.store_path != null
    && builtins.match "/nix/store/.*" value.inputs.evaluator.store_path != null
    && builtins.match "/nix/store/.*" value.inputs.host_nix.store_path != null
    && builtins.match "/nix/store/.*" value.inputs.instance_facts.store_path != null;
in
  assert validShape fixture;
  assert exactOwnershipCoverage fixture;
  assert validInputs fixture;
  assert validShape actual;
  assert exactOwnershipCoverage actual;
  assert validInputs actual;
  assert !(lib.isDerivation actual);
    pkgs.mkDerivation {
      pname = "aos-config-manifest-contract-check";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p $out
            echo PASS > $out/result
          '';
        }
      ];
    }
