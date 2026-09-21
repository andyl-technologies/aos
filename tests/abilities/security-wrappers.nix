##! Checks package-owned privileged wrapper requests.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos;
    implementation = "privileged-executable";
  };
  evaluated = lib.evalModules {
    inherit lib pkgs;
    modules = [
      lib.abilities.module
      ../../modules/_package-contributions.nix
      {
        aos.security.sudo.enable = true;
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
        module = pkgs.aos.module + "/privileged-executable.nix";
      }
      (lib.abilities.authenticatedPackageModuleRecordFor pkgs.sudo)
    ];
    selectedProviderModules = [selectedProvider];
    specialArgs.provenance = {
      dependencyOwnersOfAttr = _: _: [];
      ownerOfListAttr = _: _: _: "@test";
    };
  };
  requests = evaluated.config.aos.abilities.requests;
  provide = evaluated.config.aos.abilities.implementations."aos:privileged-executable".provide;
  requestName = "sudo:wrapper-sudo";
  sudo = requests."sudo:wrapper-sudo".parameters;
  binding = {
    request = requestName;
    implementation = "aos:privileged-executable";
    providerInstance = "aos:privileged-executable";
    slot = "wrapper-sudo";
  };
  context = children: {
    inherit children;
    requests.${requestName} = requests.${requestName};
    bindings.selected = binding;
  };
  rootResource = {
    interface = serviceManagement.interfaces.filesystemEntry.identity;
    resource = {
      provider = {
        environment = {
          authority = "test";
          key = "security-wrappers";
          stage = "host";
        };
        package = "aos-filesystem-provider";
        key = "filesystem";
      };
      key = "wrapper-root";
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  binResource = rootResource // {resource = rootResource.resource // {key = "wrapper-bin";};};
  entryResource = rootResource // {resource = rootResource.resource // {key = "wrapper-sudo";};};
  rootChild.outputs.resource.value = rootResource;
  binChild.outputs.resource.value = binResource;
  entryChild.outputs = {
    planned-path.value = "/run/wrappers/bin/sudo";
    resource.value = entryResource;
  };
  rootStage = provide (context {});
  binStage = provide (context {wrapper-root = rootChild;});
  entryStage = provide (context {
    wrapper-root = rootChild;
    wrapper-bin = binChild;
  });
  complete = provide (context {
    wrapper-root = rootChild;
    wrapper-bin = binChild;
    entry-wrapper-sudo = entryChild;
  });
  serviceManagement = lib.abilities.interfaces.serviceManagement;
in
  assert !(requests ? "aos:wrapper-root");
  assert !(requests ? "aos:wrapper-bin");
  assert requests."sudo:wrapper-sudo".requirement == "sudo:privileged-executable";
  assert sudo.source
  == {
    artifact = lib.abilities.packageOutput {package = "sudo";};
    path = "bin/sudo";
  };
  assert sudo.owner == "root";
  assert sudo.group == "root";
  assert sudo.mode == "4755";
  assert sudo.maximum_size_bytes == lib.abilities.types.limits.maxSafeInteger;
  assert requests."sudo:wrapper-sudoedit".parameters.source == sudo.source;
  assert evaluated.config.aos.abilities.implementations."aos:privileged-executable".providerModule.path
  == "privileged-executable-provider.nix";
  assert builtins.attrNames rootStage.requests == ["wrapper-root"];
  assert builtins.attrNames binStage.requests == ["wrapper-bin" "wrapper-root"];
  assert entryStage.requests.entry-wrapper-sudo.parameters.destination
  == "/run/wrappers/bin/sudo";
  assert entryStage.requests.entry-wrapper-sudo.owner_request == requestName;
  assert entryStage.requests.entry-wrapper-sudo.parameters.prerequisites == [binResource];
  assert complete.outputs.${requestName}.planned-path == "/run/wrappers/bin/sudo";
  assert complete.outputs.${requestName}.resource == entryResource; true
