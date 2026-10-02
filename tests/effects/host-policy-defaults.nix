##! Preserves default host networking and selected baseline security policies.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    outPath = toString (import ./_fixture-payload.nix "host-policy-defaults");
    meta.mainProgram = "handler";
  };
  evaluateWithHostPolicy = includeHostPolicy: overrides:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules =
        [
          ../../lib/effects/module.nix
          ../../pkgs/system/_service-management/module.nix
          ../../pkgs/system/_aos-host-policy/networking.nix
          ../../pkgs/networking/_nftables/module.nix
          ../../pkgs/security/_audit/module.nix
          ({lib, ...}: {
            options.aos.kernel.sysctl = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
            };
            options.aos.kernel.commandLineParts = lib.mkOption {
              type = lib.types.attrsOf (lib.types.listOf lib.types.str);
              default = {};
            };
            aos.abilities = {
              network.operations.configure.handler.program = package;
              networkPolicy.operations.ruleset.handler.program = package;
              serviceManagement.operations.realize.handler.program = package;
              configuration.operations.file.handler.program = package;
            };
          })
          overrides
        ]
        ++ lib.optional includeHostPolicy ../../pkgs/system/_aos-host-policy/security-baseline.nix;
    };
  evaluate = evaluateWithHostPolicy true;
  primitive = evaluateWithHostPolicy false {};
  defaults = evaluate {};
  disabled = evaluate {
    aos.security.audit.enable = false;
    aos.networkPolicy.enable = false;
  };
  explicit = evaluate {aos.networking.interfaces.eth0.address = "192.0.2.5/24";};
  links = evaluated: evaluated.config.aos.abilities.network.operations.configure.effects.host.input.links;
  defaultLink = builtins.head (links defaults);
  explicitLink = builtins.head (links explicit);
  graph = defaults.config.aos.activation.graph;
in {
  standaloneFirewallContractIsInert = !primitive.config.aos.networkPolicy.enable && !(primitive.config.aos.abilities.networkPolicy.operations.ruleset.effects ? host);
  defaultEthernetNames =
    defaultLink.selector
    == {
      kind = "ethernet";
      value = "en*";
    };
  defaultDhcpLeasePolicy = defaultLink.addressing.dhcp && defaultLink.addressing.dhcp_use_dns && defaultLink.addressing.dhcp_use_ntp && defaultLink.addressing.dhcp_use_domains == "yes";
  explicitSelectorPreserved =
    explicitLink.selector
    == {
      kind = "name";
      value = "eth0";
    };
  explicitDhcpPolicyUnchanged = explicitLink.addressing.dhcp_use_dns == null && explicitLink.addressing.dhcp_use_ntp == null && explicitLink.addressing.dhcp_use_domains == null;
  baselineFirewallEnabled = defaults.config.aos.networkPolicy.enable && defaults.config.aos.abilities.networkPolicy.operations.ruleset.effects.host.enable;
  baselineAuditEnabled = defaults.config.aos.security.audit.enable && defaults.config.aos.services."audit.auditd".enable && defaults.config.aos.services."audit.audit-rules".enable;
  explicitSecurityDisablePreserved = disabled.config.aos.abilities.networkPolicy.operations.ruleset.effects == {} && disabled.config.aos.abilities.serviceManagement.operations.realize.effects == {};
  defaultGraphChecked = builtins.deepSeq graph true;
}
