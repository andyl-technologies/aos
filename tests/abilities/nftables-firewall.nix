##! Pure evaluation checks for the provider-neutral host firewall policy.
{
  lib,
  pkgs,
}: let
  evaluate = firewallConfig:
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
              key = "nftables-firewall-test";
              stage = "host";
            };
            aos.firewall = firewallConfig;
          };
        })
      ];
      packageModules = [
        {
          name = "nftables";
          inherit (pkgs.nftables) version;
          module = pkgs.nftables.module + "/module.nix";
        }
      ];
    };

  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    defaultPolicy = "drop";
    allowedTCP = [22 443];
    allowedUDP = [41641];
    forwardPolicy = "accept";
    trustedInterfaces = ["lo" "tailscale0"];
  };
  changed = evaluate {
    enable = true;
    defaultPolicy = "drop";
    allowedTCP = [22 443 8443];
    allowedUDP = [41641];
    forwardPolicy = "accept";
    trustedInterfaces = ["lo" "tailscale0"];
  };
  packageProjection = pkgs.nftables.abilities;
  packageContract = pkgs.nftables.contract.value;
  documentedOptionPaths =
    builtins.map
    (option: lib.concatStringsSep "." option.path)
    packageContract.option_declarations;
  request = enabled.config.aos.abilities.requests."nftables:ruleset";
in
  assert enabled.config.aos.abilities.runtimeChecks."nftables:firewall".description
  == "nftables firewall checks";
  assert builtins.attrNames packageProjection.interfaces == [];
  assert builtins.attrNames packageProjection.implementations == [];
  assert documentedOptionPaths
  == [
    "aos.firewall.allowedTCP"
    "aos.firewall.allowedUDP"
    "aos.firewall.defaultPolicy"
    "aos.firewall.enable"
    "aos.firewall.forwardPolicy"
    "aos.firewall.trustedInterfaces"
  ];
  assert builtins.all
  (option: option.source.path == "module.nix" && option.description != "")
  packageContract.option_declarations;
  assert packageContract.package_module
  == {
    artifact = {
      package = "nftables";
      output = "module";
    };
    path = "module.nix";
  };
  assert pkgs.nftables ? module;
  assert disabled.config.aos.abilities.instances == {};
  assert disabled.config.aos.abilities.requests == {};
  assert enabled.config.aos.abilities.instances ? "nftables:firewall";
  assert builtins.attrNames enabled.config.aos.abilities.requests == ["nftables:ruleset"];
  assert request.parameters
  == {
    base = {
      input_policy = "drop";
      forward_policy = "accept";
      trusted_interfaces = ["lo" "tailscale0"];
      prerequisites = [];
    };
    ingress.firewall-defaults = {
      endpoints = [
        {
          transport = "tcp";
          port = 22;
        }
        {
          transport = "udp";
          port = 41641;
        }
        {
          transport = "tcp";
          port = 443;
        }
      ];
      prerequisites = [];
    };
    forwarding = {};
  };
  assert request.parameters != changed.config.aos.abilities.requests."nftables:ruleset".parameters; true
