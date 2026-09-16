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
      }
    ];
    packageModules = [
      (packageModule pkgs.aos-boot-preparations)
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
  assert (request "aos-boot-preparations" "network-wait-online-unit").source.unit_file
  == "lib/systemd/system/systemd-networkd-wait-online.service";
  assert builtins.elem
  (output "aos-boot-preparations" "initrd-stage" "readiness-resource")
  mountVar.requires;
  assert mountVar.required_by
  == [(output "aos-boot-preparations" "initrd-filesystems" "readiness-resource")];
  assert provisioningEffects.handlerDescriptor.entryPoint
  == "bin/aos-storage-provisioning-provider";
  assert (request "aos-boot-preparations" "initrd-stage").milestone
  == "initrd-stage-executed"; true
