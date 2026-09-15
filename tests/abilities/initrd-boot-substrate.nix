##! Package-owned initrd boot-substrate and repart lifecycle declarations.
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
        aos.storage.provisioningService.enable = true;
      }
    ];
    packageModules = [
      (packageModule pkgs.aos-boot-preparations)
      (packageModule pkgs.aos-storage-provisioning-provider)
      (packageModule pkgs.systemd)
    ];
  };
  requests = evaluated.config.aos.abilities.requests;
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
  repart = request "aos-storage-provisioning-provider" "aos-repart-dependencies";
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
  (output "aos-boot-preparations" "partition-layout" "readiness-resource")
  mountVar.requires;
  assert mountVar.required_by
  == [(output "aos-boot-preparations" "initrd-filesystems" "readiness-resource")];
  assert builtins.elem
  (output "aos-storage-provisioning-provider" "provisioning-plan" "readiness-resource")
  repart.requires;
  assert builtins.elem
  (output "aos-storage-provisioning-provider" "root-a-device" "readiness-resource")
  repart.requires;
  assert repart.required_by
  == [(output "aos-storage-provisioning-provider" "initrd-root-filesystems" "readiness-resource")]; true
