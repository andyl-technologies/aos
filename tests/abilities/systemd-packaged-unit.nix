##! Fixed-point evaluation of the systemd-owned packaged-unit provider.
{
  lib,
  pkgs,
}: let
  interfaceModule = ../../pkgs/system/_systemd-abilities.nix;
  providerModule = ../../pkgs/system/_systemd-provider.nix;
  artifact = lib.abilities.packageOutput {};
  declaration =
    (import interfaceModule {inherit lib;}).config.aos.abilities.interfaces.systemd-packaged-unit;
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  consumerModuleFor = unitFile: {
    config.aos.abilities = {
      requirementTemplates.unit = {
        interface = identity.name;
        inherit (identity) abi descriptor;
        methods = ["apply" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      instances.consumer = {};
      requests.unit = {
        requirement = "unit";
        consumer = "consumer";
        scope = [];
        parameters = {
          source = {
            inherit artifact;
            unit_file = unitFile;
          };
          activation = "enabled";
          dependencies = {
            after = [];
            before = [];
            requires = [];
            wants = [];
          };
          drop_in = {
            accepted_exit_statuses = [0 2];
            reload_triggers = [];
            search_path = [artifact];
          };
        };
      };
    };
  };

  evaluate = consumerModule:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-packaged-unit";
              stage = "host";
            };
            bindings."test:unit" = {
              request = "consumer:unit";
              implementation = "systemd:systemd-packaged-unit";
              providerInstance = "systemd:manager";
              slot = "example";
            };
          };
        }
      ];
      packageModules = [
        {
          name = "systemd";
          module = {
            imports = [interfaceModule providerModule];
            config.aos.abilities.instances.manager = {};
          };
        }
        {
          name = "consumer";
          module = consumerModule;
        }
      ];
      specialArgs = {
        packageName = "systemd";
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
        artifactLocatorFor = selector:
          if (selector._type or null) != "aos-package-output-selector"
          then throw "provider attempted to resolve a materialized artifact reference"
          else {
            artifactReference = {
              _type = "aos-artifact-reference";
              content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
              nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
              closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
            };
            path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
          };
      };
    };

  evaluation = evaluate (consumerModuleFor "lib/systemd/system/example.service");
  invalidUnitName = builtins.tryEval (builtins.deepSeq (
      builtins.head (
        builtins.attrValues (
          (evaluate (consumerModuleFor "lib/systemd/system/not-a-unit"))
          .config
          .aos
          .abilities
          .desiredResources
        )
      )
    )
    true);

  abilities = evaluation.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  unit = evaluation.config.systemd.units."example.service";
  source = builtins.head evaluation.config.systemd.packagedUnitSources;
  rendered = evaluation.config.system.build.systemdUnitBodies."example.service";
in
  assert desired.realization.systemd_unit.unit_name == "example.service";
  assert desired.realization.source.artifact.store_path == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
  assert source.artifactRoot == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
  assert source.unitFile == "lib/systemd/system/example.service";
  assert source.unitName == "example.service";
  assert unit.overrideStrategy == "asDropin";
  assert unit.wantedBy == ["multi-user.target"];
  assert unit.text == desired.realization.drop_in_text;
  assert !(lib.hasInfix "Documentation=" unit.text);
  assert !(desired.realization ? revision_receipt);
  assert lib.hasInfix "SuccessExitStatus=0 2" desired.realization.drop_in_text;
  assert lib.hasInfix "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example/bin" unit.text;
  assert lib.hasInfix "SuccessExitStatus=0 2" rendered.text;
  assert !invalidUnitName.success; true
