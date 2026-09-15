##! Checks system-owned service modules at their typed ability boundary.
{lib}: let
  systemdProvider = import ../../pkgs/system/_systemd-service-provider-lib.nix {inherit lib;};
  evaluate = {
    allowedTCP,
    allowedUDP,
  }:
    lib.evalModules {
      specialArgs = {
        inherit lib;
        pkgs.nftables = builtins.toFile "nftables-test" "";
      };
      modules = [
        ../../modules/abilities/default.nix
        ({lib, ...}: {
          options.system.checks = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          config.aos.abilities.environment = {
            authority = "deployment";
            key = "module-test";
            stage = "host";
          };
        })
        ../../modules/security/firewall.nix
        {
          aos.firewall = {
            enable = true;
            inherit allowedTCP allowedUDP;
          };
        }
      ];
    };
  baseline = evaluate {
    allowedTCP = [22 443];
    allowedUDP = [53];
  };
  changed = evaluate {
    allowedTCP = [22 443 8443];
    allowedUDP = [53];
  };
  requestNames = [
    "system:firewall-ruleset"
    "system:nftables-configuration"
    "system:nftables-dependencies"
    "system:nftables-lifecycle"
    "system:nftables-reload"
  ];
  requestsFor = evaluated: evaluated.config.aos.abilities.requests;
  serviceProjectionFor = evaluated: let
    requests = requestsFor evaluated;
  in
    builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = requests.${name};
      })
      requestNames);
  resourceIdFor = evaluated: let
    config = evaluated.config;
    lifecycle = (requestsFor evaluated)."system:nftables-lifecycle".parameters;
  in
    systemdProvider.normalizedResourceId {
      provider = {
        environment = config.aos.abilities.environment;
        key = "systemd";
      };
      key = lifecycle.service;
    };
  inherit (baseline) config;
  requests = requestsFor baseline;
  lifecycle = requests."system:nftables-lifecycle".parameters;
  dependencies = requests."system:nftables-dependencies".parameters;
  reload = requests."system:nftables-reload".parameters;
  configuration = requests."system:nftables-configuration".parameters;
  materialization = requests."system:firewall-ruleset".parameters;
  executionPath = {
    _type = "aos-request-output-reference";
    request = "system:firewall-ruleset";
    output = "planned-path";
  };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {package = "nftables";};
      entry_point = "sbin/nft";
      inherit arguments;
    };
    ignore_failure = false;
  };
in
  assert !(config ? systemd);
  assert !(config ? environment);
  assert materialization.source.kind == "inline-text";
  assert materialization.mode == "0444";
  assert lib.hasInfix "elements = { 22, 443 }" materialization.source.content;
  assert lib.hasInfix "elements = { 53 }" materialization.source.content;
  assert lifecycle.start == [(command ["-f" executionPath])];
  assert lifecycle.configuration_change_action == "reload";
  assert lifecycle.execution_model == "oneshot";
  assert lifecycle.remain_after_exit;
  assert lifecycle.restart == "never";
  assert lifecycle.stop == [(command ["flush" "ruleset"])];
  assert reload.commands == lifecycle.start;
  assert configuration.views == [{
    name = "ruleset";
    source = executionPath;
    optional = false;
  }];
  assert dependencies.after == [{
    _type = "aos-request-output-reference";
    request = "system:firewall-filesystems";
    output = "readiness-resource";
  }];
  assert dependencies.before == [{
    _type = "aos-request-output-reference";
    request = "system:firewall-network-stack";
    output = "readiness-resource";
  }];
  assert dependencies.before == dependencies.wants;
  assert requests."system:firewall-filesystems".parameters.scope == "local-filesystems";
  assert requests."system:firewall-network-stack".parameters.scope == "stack-prepared";
  assert materialization.source.content != (requestsFor changed)."system:firewall-ruleset".parameters.source.content;
  assert serviceProjectionFor baseline != serviceProjectionFor changed;
  assert resourceIdFor baseline == resourceIdFor changed;
  true
