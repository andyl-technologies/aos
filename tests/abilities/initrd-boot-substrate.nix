##! Package-owned initrd boot-substrate and checked provisioning declarations.
{
  lib,
  pkgs,
}: let
  packageModule = package: {
    name = package.pname;
    inherit (package) version;
    module = package.module + "/module.nix";
  };
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
          request = {
            name = "first-boot";
            enabled = true;
            root_device = "/dev/disk/by-partlabel/root-a";
            measured_boot = false;
            policy = {
              initialize = "if-unprovisioned";
              committed_divergence = "require-factory-reset";
            };
            prerequisites = [];
          };
        };
      }
    ];
    packageModules = [
      (packageModule pkgs.aos-boot-preparations)
      (packageModule pkgs.aos)
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
  provisioning = request "aos" "provisioning";
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
  assert (request "aos-boot-preparations" "network-wait-online-unit").source.unit_file
  == "lib/systemd/system/systemd-networkd-wait-online.service";
  assert builtins.elem
  (output "aos-boot-preparations" "initrd-stage" "readiness-resource")
  mountVar.requires;
  assert mountVar.required_by
  == [(output "aos-boot-preparations" "initrd-filesystems" "readiness-resource")];
  assert provisioningEffects.handlerDescriptor.entryPoint
  == "bin/aos-storage-provisioning-provider";
  assert provisioning
  == {
    name = "first-boot";
    enabled = true;
    root_device = "/dev/disk/by-partlabel/root-a";
    measured_boot = false;
    policy = {
      initialize = "if-unprovisioned";
      committed_divergence = "require-factory-reset";
    };
    prerequisites = [];
  };
  assert implementations."aos:storage-provisioning-platform-detector".handlerDescriptor.entryPoint
  == "libexec/aos-metadata-provisioning-provider";
  assert implementations."aos:storage-provisioning-input-authorizer".handlerDescriptor.entryPoint
  == "libexec/aos-metadata-provisioning-provider";
  assert (request "aos-boot-preparations" "initrd-stage").milestone
  == "initrd-stage-executed"; true
