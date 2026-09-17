##! Checks package-owned privileged wrapper requests.
{
  lib,
  pkgs,
}: let
  evaluated = lib.evalModules {
    inherit lib pkgs;
    modules = [
      lib.abilities.module
      ../../modules/_package-contributions.nix
      {
        options.aos.security.sudo.enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        aos.abilities.environment = {
          authority = "deployment";
          key = "wrapper-test";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "aos";
        version = pkgs.aos.version;
        module = pkgs.aos.module + "/runtime-layout.nix";
      }
      (lib.abilities.authenticatedPackageModuleRecordFor pkgs.sudo)
    ];
  };
  requests = evaluated.config.aos.abilities.requests;
  wrapperRoot = requests."aos:wrapper-root".parameters;
  wrapperBin = requests."aos:wrapper-bin".parameters;
  sudo = requests."sudo:wrapper-sudo".parameters;
in
  assert wrapperRoot.entry.kind == "directory";
  assert wrapperRoot.destination == "/run/wrappers";
  assert wrapperRoot.prerequisites == [];
  assert wrapperBin.entry.kind == "directory";
  assert wrapperBin.destination == "/run/wrappers/bin";
  assert wrapperBin.prerequisites == [(lib.abilities.resultOf "aos:wrapper-root" "resource")];
  assert sudo.entry
  == {
    kind = "copied-file";
    source = {
      kind = "artifact-file";
      reference = {
        artifact = lib.abilities.packageOutput {package = "sudo";};
        path = "bin/sudo";
      };
    };
    maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
  };
  assert sudo.destination == "/run/wrappers/bin/sudo";
  assert sudo.owner == "root";
  assert sudo.group == "root";
  assert sudo.mode == "4755";
  assert sudo.prerequisites == [(lib.abilities.resultOf "aos:wrapper-bin" "resource")];
  assert requests."sudo:wrapper-sudoedit".parameters.entry == sudo.entry; true
