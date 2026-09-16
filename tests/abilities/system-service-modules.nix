##! Checks the package-owned firewall module at its typed ability boundary.
{
  lib,
  pkgs,
}: let
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "service-lifecycle";
  };
  serviceEffectsRequest = lib.abilities.compositionRequestKey {
    implementation = "systemd:service-lifecycle";
    providerInstance = "systemd:manager";
    key = "nftables";
  };
  nftables = pkgs.nftables;
  evaluate = {
    allowedTCP,
    allowedUDP,
    realizeService ? false,
  }:
    lib.evalModules {
      specialArgs = {
        inherit lib pkgs;
      };
      modules =
        [
          ../../modules/abilities/default.nix
          ({lib, ...}: {
            options.environment.systemPackages = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
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
        ]
        ++ lib.optionals realizeService [
          ./_systemd-platform-module.nix
          {
            aos.abilities = {
              instances."systemd:manager" = {};
              bindings = {
                "test:lifecycle" = {
                  request = "nftables:nftables-lifecycle";
                  implementation = "systemd:service-lifecycle";
                  providerInstance = "systemd:manager";
                  slot = "nftables";
                };
                "test:service-effects" = {
                  request = serviceEffectsRequest;
                  implementation = "systemd:systemd-service-effects";
                  providerInstance = "systemd:manager";
                  slot = "nftables";
                };
              };
            };
          }
        ];
      packageModules =
        [
          {
            name = "nftables";
            inherit (pkgs.nftables) version;
            module = pkgs.nftables.module + "/module.nix";
          }
        ]
        ++ lib.optional realizeService {
          name = "systemd";
          inherit (pkgs.systemd) version;
          module = pkgs.systemd.module + "/module.nix";
        };
      selectedProviderModules = lib.optional realizeService selectedSystemdProvider;
    };
  baseline = evaluate {
    allowedTCP = [22 443];
    allowedUDP = [53];
  };
  changed = evaluate {
    allowedTCP = [22 443 8443];
    allowedUDP = [53];
  };
  realizedBaseline = evaluate {
    allowedTCP = [22 443];
    allowedUDP = [53];
    realizeService = true;
  };
  realizedChanged = evaluate {
    allowedTCP = [22 443 8443];
    allowedUDP = [53];
    realizeService = true;
  };
  requestNames = [
    "nftables:ruleset"
    "nftables:nftables-configuration"
    "nftables:nftables-dependencies"
    "nftables:nftables-lifecycle"
    "nftables:nftables-reload"
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
  serviceResourceFor = evaluated: let
    resources =
      builtins.filter
      (resource: resource.controller == "test:lifecycle")
      (builtins.attrValues evaluated.config.aos.abilities.desiredResources);
  in
    if builtins.length resources != 1
    then throw "nftables lifecycle did not resolve to one public service resource"
    else builtins.head resources;
  inherit (baseline) config;
  requests = requestsFor baseline;
  lifecycle = requests."nftables:nftables-lifecycle".parameters;
  dependencies = requests."nftables:nftables-dependencies".parameters;
  reload = requests."nftables:nftables-reload".parameters;
  configuration = requests."nftables:nftables-configuration".parameters;
  materialization = requests."nftables:ruleset".parameters;
  executionPath = {
    _type = "aos-request-output-reference";
    request = "nftables:ruleset";
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
  assert config.environment.systemPackages == [nftables];
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
  assert configuration.views
  == [
    {
      name = "ruleset";
      source = executionPath;
      optional = false;
    }
  ];
  assert dependencies.after
  == [
    {
      _type = "aos-request-output-reference";
      request = "nftables:local-filesystems";
      output = "readiness-resource";
    }
  ];
  assert dependencies.before
  == [
    {
      _type = "aos-request-output-reference";
      request = "nftables:network-readiness";
      output = "readiness-resource";
    }
  ];
  assert dependencies.before == dependencies.wants;
  assert requests."nftables:local-filesystems".parameters.scope == "local-filesystems";
  assert requests."nftables:network-readiness".parameters.scope == "stack-prepared";
  assert materialization.source.content != (requestsFor changed)."nftables:ruleset".parameters.source.content;
  assert serviceProjectionFor baseline != serviceProjectionFor changed;
  assert (serviceResourceFor realizedBaseline).resource == (serviceResourceFor realizedChanged).resource; true
