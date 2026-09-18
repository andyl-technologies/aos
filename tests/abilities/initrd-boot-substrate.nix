##! Package-owned initrd boot-substrate and checked provisioning declarations.
{
  lib,
  pkgs,
}: let
  milestones = lib.abilities.interfaces.serviceManagement.milestones;
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor;
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities.environment = {
          authority = "test";
          key = "initrd-boot-substrate";
          stage = "initrd";
        };
        aos.boot.substrateServices.enable = true;
        aos.metadata.storageProvisioning = {
          authorizationConfiguration = {
            schema = "aos.metadata.provisioning-authorization-configuration/v1";
            trust_mode = "platform";
            trusted_config_keys = [];
            base_library = {
              store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-base-lib";
              abi_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            };
          };
        };
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
  requests = evaluated.config.aos.abilities.requests;
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
  == milestones.initrdStageExecuted; true
