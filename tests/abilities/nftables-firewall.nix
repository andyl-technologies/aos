##! Pure evaluation checks for the package-owned nftables firewall declaration.
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
        ../../modules/security/firewall.nix
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
  packageProjection = pkgs.nftables.abilities;
  packageContract = pkgs.nftables.contract.value;
  documentedOptionPaths =
    builtins.map
    (option: lib.concatStringsSep "." option.path)
    packageContract.option_declarations;
  requests = enabled.config.aos.abilities.requests;
  configuration = requests."nftables:ruleset".parameters.source.content;
  lifecycle = requests."nftables:nftables-lifecycle".parameters;
in
  assert enabled.config.environment.systemPackages == [pkgs.nftables];
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
      package = "self";
      output = "module";
    };
    path = "module.nix";
  };
  assert pkgs.nftables ? module;
  assert disabled.config.aos.abilities.instances == {};
  assert disabled.config.aos.abilities.requests == {};
  assert enabled.config.aos.abilities.instances ? "nftables:service";
  assert requests ? "nftables:local-filesystems";
  assert requests ? "nftables:network-readiness";
  assert requests ? "nftables:ruleset";
  assert lib.hasInfix "elements = { 22, 443 }" configuration;
  assert lib.hasInfix "elements = { 41641 }" configuration;
  assert lib.hasInfix ''iifname "tailscale0" accept'' configuration;
  assert lib.hasInfix "type filter hook forward priority 0; policy accept;" configuration;
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "nftables";};
        entry_point = "sbin/nft";
        arguments = [
          "-f"
          {
            _type = "aos-request-output-reference";
            request = "nftables:ruleset";
            output = "planned-path";
          }
        ];
      };
      ignore_failure = false;
    }
  ]; true
