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
      specialArgs = {
        inherit package;
        dependencies = {
          coreutils = package;
          ca-certificates = package;
        };
        provenance = {
          ownerOfOption = _: "@base";
          ownerOfListAttr = _: _: _: "@base";
        };
      };
      modules =
        [
          ../../lib/effects/module.nix
          ../../pkgs/system/_service-management/module.nix
          ../../pkgs/system/_init-system/module.nix
          ../../pkgs/system/_kmod-abilities/module.nix
          ../../pkgs/tools/_aos-kernel-tunable-provider/module.nix
          ../../pkgs/system/_aos-host-policy/kernel.nix
          ../../pkgs/system/_aos-host-policy/hardening.nix
          ../../pkgs/system/_systemd-abilities/crash-dump-policy.nix
          ../../pkgs/boot/_aos-configuration-lower/module.nix
          ../../pkgs/system/_aos-host-policy/configuration-lower.nix
          ../../pkgs/system/_aos-host-policy/pki.nix
          ../../pkgs/system/_aos-host-policy/networking.nix
          ../../pkgs/networking/_nftables/module.nix
          ../../pkgs/security/_audit/module.nix
          ({lib, ...}: {
            options.environment.sessionVariables = lib.mkOption {
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
  container = evaluate {aos.initSystem.container = true;};
  explicitContainer = evaluate {
    aos.initSystem.container = true;
    aos.kernel.bbr = true;
    aos.kernel.sysctl."vm.swappiness" = "25";
    aos.security.hardening.sysctl."kernel.kptr_restrict" = "1";
    aos.networking = {
      hostName = "authored-container";
      tuning."net.core.somaxconn" = "1024";
      interfaces.eth0.address = "192.0.2.6/24";
    };
    aos.networkPolicy.enable = true;
  };
  containerCollector = evaluate {
    aos.initSystem.container = true;
    aos.security.hardening.coreDump.enable = true;
  };
  explicitLower = evaluate {
    aos.initSystem.container = true;
    aos.configurationLower.enable = true;
  };
  explicitLowerFile = evaluate {
    aos.initSystem.container = true;
    aos.configurationLower.files."requested.conf" = {
      kind = "text";
      text = "requested";
    };
  };
  containerLowerBackend = evaluate {
    aos.initSystem.container = true;
    aos.configurationLower.enable = true;
    aos.abilities.configurationLower.operations.mount.handler.program = package;
  };
  explicitTree = evaluate {
    aos.initSystem.container = true;
    aos.filesystems.etcTrees = [
      {
        target = "requested-tree";
        source = package.outPath;
      }
    ];
  };
  explicitPki = evaluate {
    aos.initSystem.container = true;
    aos.security.pki.enable = true;
  };
  customPki = evaluate {
    aos.initSystem.container = true;
    aos.security.pki.certificates = ["custom certificate"];
    aos.security.pki.certificateFiles = [package.outPath];
  };
  lowerPreflightRejected = evaluated:
    evaluated.config.aos.configurationLower.enable
    && evaluated.config.aos.abilities.configurationLower.operations.install.effects.image.children.overlay.execution.program == null
    && !(builtins.tryEval (builtins.deepSeq evaluated.config.aos.activation.graph true)).success;
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
  hostKernelDefaultsUnchanged =
    defaults.config.aos.kernel.bbr
    && defaults.config.aos.kernel.sysctl."fs.inotify.max_user_instances" == "8192"
    && defaults.config.aos.kernel.sysctl."kernel.kptr_restrict" == "2"
    && defaults.config.aos.kernel.sysctl."kernel.hostname" == "aos"
    && defaults.config.aos.kernel.sysctl."kernel.core_pattern" == "|${package}/bin/false";
  containerKernelDefaultsAreInert =
    !container.config.aos.kernel.bbr
    && container.config.aos.kernel.sysctl == {}
    && container.config.aos.abilities.kernelTunables.operations.ensure.effects == {}
    && container.config.aos.abilities.kernelModules.operations.ensure.effects == {};
  containerNetworkDefaultsAreInert =
    !container.config.aos.networking.useDHCP
    && !container.config.aos.networking.resolved.enable
    && container.config.aos.networking.hostName == null
    && container.config.aos.abilities.network.operations.configure.effects == {}
    && !container.config.aos.networkPolicy.enable;
  containerUserspaceHardeningRemains =
    container.config.aos.security.hardening.enable
    && container.config.aos.abilities.configuration.operations.file.effects.hardening-limits.enable
    && container.config.aos.abilities.configuration.operations.file.effects.coredump-policy.enable
    && builtins.match ".*Storage=none.*" container.config.aos.security.hardening.crashFiles."systemd/coredump.conf".text != null;
  explicitContainerKernelPolicyIsRetained =
    explicitContainer.config.aos.kernel.bbr
    && explicitContainer.config.aos.kernel.sysctl."vm.swappiness" == "25"
    && explicitContainer.config.aos.kernel.sysctl."kernel.kptr_restrict" == "1"
    && explicitContainer.config.aos.kernel.sysctl."net.core.somaxconn" == "1024"
    && explicitContainer.config.aos.kernel.sysctl."kernel.hostname" == "authored-container"
    && explicitContainer.config.aos.abilities.kernelTunables.operations.ensure.effects.settings.enable
    && explicitContainer.config.aos.abilities.kernelModules.operations.ensure.effects.kernel-policy.enable;
  explicitContainerNetworkingIsRetained =
    (builtins.head (links explicitContainer)).addressing.addresses
    == ["192.0.2.6/24"]
    && explicitContainer.config.aos.networkPolicy.enable
    && explicitContainer.config.aos.abilities.networkPolicy.operations.ruleset.effects.host.enable;
  explicitContainerCollectorIsRetained =
    containerCollector.config.aos.kernel.sysctl."kernel.core_pattern"
    == "|${package}/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e"
    && containerCollector.config.aos.abilities.kernelTunables.operations.ensure.effects.settings.enable;
  hostConfigurationLowerUnchanged =
    defaults.config.aos.configurationLower.enable
    && defaults.config.aos.security.pki.enable
    && defaults.config.aos.configurationLower.files ? "security/limits.d/aos-hardening.conf"
    && defaults.config.aos.configurationLower.files ? "ssl/certs/ca-certificates.crt"
    && defaults.config.aos.abilities.configurationLower.operations.mount.handler.program != null;
  containerLiteralFilesRemainLive =
    !container.config.aos.configurationLower.enable
    && container.config.aos.configurationLower.files == {}
    && container.config.aos.abilities.configuration.operations.file.effects.hardening-limits.enable
    && container.config.aos.abilities.configuration.operations.file.effects.coredump-policy.enable;
  containerRetainsCanonicalCAIdentity =
    !container.config.aos.security.pki.enable
    && container.config.aos.security.pki.caBundle == "/etc/ssl/certs/ca-certificates.crt";
  explicitContainerLowerRejectedBeforeDispatch = lowerPreflightRejected explicitLower;
  explicitContainerLowerFileRejectedBeforeDispatch = lowerPreflightRejected explicitLowerFile;
  containerCanSelectLowerBackend = builtins.deepSeq containerLowerBackend.config.aos.activation.graph true;
  explicitContainerTreeRejectedBeforeDispatch =
    lowerPreflightRejected explicitTree
    && builtins.length explicitTree.config.aos.configurationLower.etcTrees == 1;
  explicitContainerPkiRejectedBeforeDispatch =
    lowerPreflightRejected explicitPki
    && explicitPki.config.aos.security.pki.enable;
  customContainerPkiRejectedBeforeDispatch =
    lowerPreflightRejected customPki
    && customPki.config.aos.security.pki.enable
    && builtins.length customPki.config.aos.configurationLower.files."ssl/certs/ca-certificates.crt".parts == 3;
  defaultGraphChecked = builtins.deepSeq graph true;
  containerGraphsChecked = builtins.deepSeq container.config.aos.activation.graph (builtins.deepSeq explicitContainer.config.aos.activation.graph true);
}
