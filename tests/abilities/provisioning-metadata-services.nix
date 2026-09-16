##! Package-owned initrd metadata lifecycle and provider dispatch.
{
  lib,
  pkgs,
}: let
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "network-readiness";
  };
  packageModule = package: {
    name = package.pname;
    inherit (package) version;
    module = package.module + "/module.nix";
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          aos.abilities = {
            environment = {
              authority = "test";
              key = "provisioning-metadata-services";
              stage = "initrd";
            };
            instances."systemd:manager" = {};
            inherit bindings;
          };
          aos.metadata.initrdServices = {
            enable = true;
            stashDir = "/run/aos-metadata";
            trust = "signed";
            trustedConfigKeysDir = "/nix/store/trusted-config-keys";
            baseLibrary = "/nix/store/aos-base-lib";
            measuredBoot = true;
          };
        }
      ];
      packageModules = [
        (packageModule pkgs.aos)
        (packageModule pkgs.systemd)
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  networkBinding = {
    "test:metadata-network" = {
      request = "aos:network-readiness";
      implementation = "systemd:network-readiness";
      providerInstance = "systemd:manager";
      slot = "metadata-network";
    };
  };
  pending = evaluate networkBinding;
  networkChild = builtins.head (builtins.filter
    (child: (child.declaration.parameters.expected.scope or null) == "configured-connectivity")
    (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests));
  evaluated = evaluate (networkBinding
    // {
      "test:metadata-network-effects" = {
        request = networkChild.request;
        implementation = "systemd:systemd-network-readiness-effects";
        providerInstance = "systemd:manager";
        slot = networkChild.slot;
      };
    });
  abilities = evaluated.config.aos.abilities;
  request = name: abilities.requests."aos:${name}".parameters;
  output = name: outputName: {
    _type = "aos-request-output-reference";
    request = "aos:${name}";
    output = outputName;
  };
  serviceNames =
    builtins.map
    (name: (request "${name}-lifecycle").service)
    [
      "aos-provisioning-state"
      "aos-metadata-detect"
      "aos-metadata-network"
      "aos-metadata-fetch"
      "aos-metadata-authorize"
      "aos-provisioning-eval"
    ];
  networkDependencies = request "aos-metadata-network-dependencies";
  authorization = request "aos-metadata-authorize-lifecycle";
  evaluation = request "aos-provisioning-eval-lifecycle";
  metadataImplementations =
    builtins.map
    (name: abilities.implementations."aos:${name}")
    [
      "storage-provisioning-platform-detector"
      "storage-provisioning-input-authorizer"
      "storage-provisioning-plan-observer"
      "storage-provisioning-configuration-evaluator"
    ];
  featureSource = builtins.readFile ../../modules/services/aos-metadata.nix;
  networkEffects = abilities.compositionRequests.${networkChild.request}.parameters;
in
  assert serviceNames
  == [
    "aos-provisioning-state"
    "aos-metadata-detect"
    "aos-metadata-network"
    "aos-metadata-fetch"
    "aos-metadata-authorize"
    "aos-provisioning-eval"
  ];
  assert builtins.elem (output "network-readiness" "readiness-resource") networkDependencies.wants;
  assert networkEffects.systemd_unit.unit_name == "network-online.target";
  assert !(lib.hasInfix "systemctl" (builtins.toJSON authorization));
  assert (builtins.head authorization.start).executable.arguments
  == [
    "authorize"
    "/run/aos-metadata"
    "signed"
    "/nix/store/trusted-config-keys"
  ];
  assert (builtins.head evaluation.start).executable.arguments
  == [
    "evaluate-provisioning"
    "/run/aos-metadata"
    "/nix/store/aos-base-lib"
    "true"
  ];
  assert builtins.all
  (implementation:
    implementation.handlerDescriptor.entryPoint
    == "libexec/aos-metadata-provisioning-provider")
  metadataImplementations;
  assert !(lib.hasInfix "boot.initrd.systemd.services" featureSource);
  assert !(lib.hasInfix "systemd.services" featureSource); true
