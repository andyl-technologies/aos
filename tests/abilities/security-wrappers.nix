##! Checks privileged wrappers at the typed filesystem-entry boundary.
{lib}: let
  evaluate = wrappers:
    lib.evalModules {
      specialArgs = {inherit lib;};
      modules = [
        ../../modules/abilities/default.nix
        ../../modules/security/wrappers.nix
        ({lib, ...}: {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          config = {
            aos.abilities.environment = {
              authority = "deployment";
              key = "wrapper-test";
              stage = "host";
            };
            aos.security.wrappers = wrappers;
          };
        })
      ];
    };
  sudoArtifact = lib.abilities.packageOutput {package = "sudo";};
  evaluated = evaluate {
    sudo = {
      source = {
        artifact = sudoArtifact;
        path = "bin/sudo";
      };
      owner = "root";
      group = "root";
      mode = "4755";
    };
    sudoedit = {
      source = {
        artifact = sudoArtifact;
        path = "bin/sudo";
      };
      owner = "root";
      group = "root";
      mode = "4755";
    };
  };
  rawStorePathRejected = !(builtins.tryEval (builtins.deepSeq (
      (evaluate {
        raw.source = "/nix/store/11111111111111111111111111111111-raw/bin/tool";
      }).config.aos.abilities.requests
    )
    true)).success;
  inherit (evaluated) config;
  requests = config.aos.abilities.requests;
  filesystemRequirement =
    config.aos.abilities.requirementTemplates."system:filesystem-entry";
  wrapperRoot = requests."system:security-wrappers".parameters;
  wrapperBin = requests."system:security-wrapper-bin".parameters;
  sudo = requests."system:security-wrapper-sudo".parameters;
in
  assert !(config ? systemd);
  assert !(config ? environment);
  assert rawStorePathRejected;
  assert filesystemRequirement.methods == ["materialize" "observe" "release"];
  assert builtins.attrNames requests
  == [
    "system:security-wrapper-bin"
    "system:security-wrapper-sudo"
    "system:security-wrapper-sudoedit"
    "system:security-wrappers"
  ];
  assert wrapperRoot.entry.kind == "directory";
  assert wrapperRoot.destination == "/run/wrappers";
  assert wrapperRoot.prerequisites == [];
  assert wrapperBin.entry.kind == "directory";
  assert wrapperBin.destination == "/run/wrappers/bin";
  assert wrapperBin.prerequisites == [{
    _type = "aos-request-output-reference";
    request = "system:security-wrappers";
    output = "retained-resource";
  }];
  assert sudo.entry
  == {
    kind = "copied-file";
    source = {
      kind = "artifact-file";
      reference = {
        artifact = sudoArtifact;
        path = "bin/sudo";
      };
    };
    maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
  };
  assert sudo.destination == "/run/wrappers/bin/sudo";
  assert sudo.owner == "root";
  assert sudo.group == "root";
  assert sudo.mode == "4755";
  assert sudo.prerequisites == [{
    _type = "aos-request-output-reference";
    request = "system:security-wrapper-bin";
    output = "retained-resource";
  }];
  true
