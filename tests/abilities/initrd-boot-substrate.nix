##! Package-owned initrd boot-substrate and checked provisioning declarations.
{
  lib,
  pkgs,
}: let
  milestones = lib.abilities.interfaces.serviceManagement.milestones;
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor;
  evaluateStage = stage:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        ../../modules/_package-domain-options.nix
        {
          aos.abilities.environment = {
            authority = "test";
            key = "initrd-boot-substrate";
            inherit stage;
          };
          aos.boot.substrateServices.enable = stage == "initrd";
          aos.boot.substrateServices.handoffEnabled = true;
        }
      ];
      packageModules = [
        (packageModule pkgs.aos-boot-preparations)
        (packageModule pkgs.aos)
        (packageModule pkgs.aos-metadata-provider)
        (packageModule pkgs.aos-nix-store-provider)
        (packageModule pkgs.aos-storage-provisioning-provider)
        (packageModule pkgs.systemd)
      ];
    };
  evaluated = evaluateStage "initrd";
  hostEvaluated = evaluateStage "host";
  requests = evaluated.config.aos.abilities.requests;
  hostRequests = hostEvaluated.config.aos.abilities.requests;
  implementations = evaluated.config.aos.abilities.implementations;
  request = package: name: requests."${package}:${name}".parameters;
  output = package: name: outputName: {
    _type = "aos-request-output-reference";
    request = "${package}:${name}";
    output = outputName;
  };
  lifecycleNames =
    builtins.map
    (name: (request "aos-boot-preparations" "${name}-lifecycle").service)
    [
      "mount-var"
      "etc-overlay-setup"
      "nix-overlay-setup"
      "aos-seed-profiles"
      "run-etc-setup"
      "aos-machine-id"
    ];
  mountVar = request "aos-boot-preparations" "mount-var-dependencies";
  provisioningEffects =
    implementations."aos-storage-provisioning-provider:storage-provisioning-effects";
  handoff = evaluated.config.aos.boot.handoffParameters;
  stageCommand = name: (request "aos-boot-preparations" "${name}-lifecycle").start;
in
  assert lifecycleNames
  == [
    "mount-var"
    "etc-overlay-setup"
    "nix-overlay-setup"
    "aos-seed-profiles"
    "run-etc-setup"
    "aos-machine-id"
  ];
  assert !(requests ? "aos:host-network");
  assert (request "aos-boot-preparations" "bootstrap-network").links
  == [
    {
      kind = "ethernet";
      name = "dhcp";
      selector.kind = "ethernet";
      addressing = {
        dhcp = true;
        addresses = [];
        dns = [];
        link_local = "ipv4";
        ipv4_link_local_route = true;
      };
    }
  ];
  assert builtins.elem
  (output "aos-boot-preparations" "initrd-stage" "resource")
  mountVar.requires;
  assert mountVar.required_by
  == [(output "aos-boot-preparations" "initrd-filesystems" "resource")];
  assert provisioningEffects.handlerDescriptor.entryPoint
  == "bin/aos-storage-provisioning-provider";
  assert implementations."aos-metadata-provider:storage-provisioning-platform-detector".handlerDescriptor.entryPoint
  == "bin/aos-metadata-acquisition-provider";
  assert implementations."aos-metadata-provider:storage-provisioning-input-authorizer".handlerDescriptor.entryPoint
  == "bin/aos-metadata-policy-provider";
  assert (request "aos-boot-preparations" "initrd-stage").milestone
  == milestones.initrdStageExecuted;
  assert handoff.completion
  == (output "aos-boot-preparations" "initrd-filesystems" "resource");
  assert builtins.elem
  (output "aos-boot-preparations" "mount-var-lifecycle" "resource")
  handoff.preparations;
  assert builtins.elem "--static-contract-identity-file"
  (builtins.head (stageCommand "aos-ability-initrd-controller")).executable.arguments;
  assert builtins.elem "--source-stage-bundle"
  (builtins.head (stageCommand "aos-ability-initrd-handoff-barrier")).executable.arguments;
  assert (request "aos-boot-preparations" "aos-ability-initrd-controller-lifecycle").remain_after_exit;
  assert (request "aos-boot-preparations" "aos-ability-initrd-handoff-barrier-lifecycle").remain_after_exit;
  assert hostRequests."aos-boot-preparations:aos-ability-host-receiver-lifecycle".parameters.remain_after_exit;
  assert !(requests ? "aos-boot-preparations:boot-preparation-handoff"); true
