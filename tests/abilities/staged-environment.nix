##! Checks that initrd contributions use a distinct ordinary ability fixed point.
{
  lib,
  pkgs,
  mkSystem,
}: let
  nixFilesUnder = directory: let
    entries = builtins.readDir directory;
  in
    builtins.concatMap (name: let
      entry = entries.${name};
      path = directory + "/${name}";
    in
      if entry == "directory"
      then nixFilesUnder path
      else if entry == "regular" && lib.hasSuffix ".nix" name
      then [path]
      else [])
    (builtins.attrNames entries);
  compact = source:
    builtins.replaceStrings [" " "\n" "\r" "\t"] ["" "" "" ""] source;
  hasLegacyInitrdIntent = source: let
    normalized = compact source;
    nestedDefinitions = builtins.tail (
      lib.splitString "aos.abilities.stages.initrd=" normalized
    );
    nestedDefinitionHasIntent = tail: let
      body = builtins.head (builtins.split "}" tail);
    in
      lib.hasPrefix "{" tail && lib.hasInfix "intent=" body;
  in
    lib.hasInfix "aos.abilities.stages.initrd.intent=" normalized
    || builtins.any nestedDefinitionHasIntent nestedDefinitions;
  productionNixFiles =
    builtins.concatMap nixFilesUnder [
      ../../lib
      ../../modules
      ../../pkgs
      ../../systems
    ]
    ++ [../../default.nix];
  legacyInitrdIntentFiles =
    builtins.filter
    (path: hasLegacyInitrdIntent (builtins.readFile path))
    productionNixFiles;
  fixturePackage = pkgs.mkDerivation {
    pname = "staged-environment-fixture";
    version = "1";
    src = null;
    abilities = ./fixtures/staged-environment-package;
    phases = [];
  };
  system = mkSystem {
    systemName = "staged-environment-test";
    modules = [
      ../../systems/_artifact-backend.nix
      ../../systems/_kernel.nix
      ../../systems/_system-manager.nix
      {
        aos.boot.initrd.packageRoots = [
          fixturePackage
          pkgs.aos-boot-preparation-provider
        ];
      }
    ];
  };
  initrd = system.config.system.build.initrdAbilityGraph;
  host = system.config.aos.abilities;
in
  assert hasLegacyInitrdIntent "aos.abilities.stages.initrd.intent = [];";
  assert hasLegacyInitrdIntent ''
    aos.abilities.stages.initrd = {
      intent = [];
    };
  '';
  assert legacyInitrdIntentFiles == [];
  assert initrd.environment
  == {
    authority = "system-image";
    key = "staged-environment-test";
    stage = "initrd";
  };
  assert initrd.requests ? "staged-environment-fixture:fixture-preparation";
  assert initrd.requests."staged-environment-fixture:fixture-preparation".parameters.execution.entry_point
  == "libexec/fixture-preparation";
  assert !(host.requests ? "staged-environment-fixture:fixture-preparation");
  assert !(builtins.any (name: lib.hasPrefix "chrony:" name) (builtins.attrNames initrd.requests));
  assert !(builtins.any (name: lib.hasPrefix "openssh:" name) (builtins.attrNames initrd.requests)); true
