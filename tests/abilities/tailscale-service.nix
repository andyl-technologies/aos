##! Pure evaluation checks for the package-owned Tailscale service declaration.
{
  lib,
  pkgs,
}: let
  evaluate = serviceConfig:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit pkgs;};
      modules = [
        ../../modules/abilities/default.nix
        ../../modules/_package-contributions.nix
        ({lib, ...}: {
          options.environment.systemPackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          options.system.checks = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };

          config = {
            aos.abilities.environment = {
              authority = "deployment";
              key = "tailscale-service-test";
              stage = "host";
            };
            aos.services.tailscale = serviceConfig;
          };
        })
      ];
      packageModules = [
        (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
        {
          name = "tailscale";
          inherit (pkgs.tailscale) version;
          module = pkgs.tailscale.module + "/module.nix";
        }
      ];
    };

  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    port = 42641;
    extraArgs = ["--no-logs-no-support"];
  };
  packageProjection = pkgs.tailscale.abilities;
  packageContract = pkgs.tailscale.contract.value;
  documentedOptionPaths =
    builtins.map
    (option: lib.concatStringsSep "." option.path)
    packageContract.option_declarations;
  requests = enabled.config.aos.abilities.requests;
  tailscaleRequests = evaluated:
    lib.filterAttrs
    (_: request: request.package == "tailscale")
    evaluated.config.aos.abilities.requests;
  tailscaleInstances = evaluated:
    lib.filterAttrs
    (_: instance: instance.package == "tailscale")
    evaluated.config.aos.abilities.instances;
  lifecycle = requests."tailscale:tailscaled-lifecycle".parameters;
in
  assert enabled.config.aos.abilities.runtimeChecks."tailscale:tailscale".description
  == "Tailscale service checks";
  assert builtins.attrNames packageProjection.interfaces == [];
  assert builtins.attrNames packageProjection.implementations == [];
  assert builtins.map (requirement: requirement.alias) packageContract.requirements
  == builtins.attrNames packageProjection.requirementTemplates;
  assert documentedOptionPaths
  == [
    "aos.services.tailscale.enable"
    "aos.services.tailscale.extraArgs"
    "aos.services.tailscale.port"
  ];
  assert builtins.all
  (option: option.source.path == "module.nix" && option.description != "")
  packageContract.option_declarations;
  assert packageContract.package_module
  == {
    artifact = {
      package = "tailscale";
      output = "module";
    };
    path = "module.nix";
  };
  assert pkgs.tailscale ? module;
  assert tailscaleInstances disabled == {};
  assert tailscaleRequests disabled == {};
  assert enabled.config.aos.abilities.instances ? "tailscale:service";
  assert requests ? "tailscale:network-readiness";
  assert requests ? "tailscale:tunnel-device";
  assert requests."tailscale:tunnel-device".parameters.device == "/dev/net/tun";
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "tailscale";};
        entry_point = "bin/tailscaled";
        arguments = [
          "--state=/var/lib/tailscale/tailscaled.state"
          "--socket=/run/tailscale/tailscaled.sock"
          "--port=42641"
          "--no-logs-no-support"
        ];
      };
      ignore_failure = false;
    }
  ]; true
