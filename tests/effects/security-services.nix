##! Verifies enabled native security consumers preserve resource ordering and policy.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "fixture";
    outPath = import ./_fixture-payload.nix "security";
    meta.mainProgram = "fixture";
    outputs.apm = import ./_fixture-payload.nix "security-apm";
    outputs.packageRuntime = import ./_fixture-payload.nix "security-runtime";
  };
  evaluated = lib.evalModules {
    inherit lib;
    specialArgs = {
      inherit package;
      packageName = "aos";
      packageVersion = "1";
      dependencies = {
        coreutils = package;
        policycoreutils = package;
        libselinux = package;
      };
    };
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/module.nix
      ../../pkgs/system/_service-management/configuration.nix
      ../../pkgs/system/_service-management/identity.nix
      ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
      ../../pkgs/security/_polkit/module.nix
      ../../pkgs/security/_sudo/module.nix
      ../../pkgs/security/_refpolicy/module.nix
      ../../pkgs/tools/aos/_abilities/attestation-verifier.nix
      ../../pkgs/tools/aos/_abilities/package-attestation-quote.nix
      ({
        lib,
        config,
        ...
      }: {
        options.aos.dbus.activationDirectories = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
        options.aos.dbus.policyDirectories = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
        options.aos.pam.packageServices = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = {};
        };
        options.aos.kernel.commandLineParts = lib.mkOption {
          type = lib.types.attrsOf (lib.types.listOf lib.types.str);
          default = {};
        };
        options.aos.filesystems.etcTrees = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [];
        };
        config = {
          aos.services.attestationVerifier.enable = true;
          aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = true;
          aos.security = {
            polkit.enable = true;
            sudo.enable = true;
            selinux.enable = true;
          };
          aos.services.dbus = {
            enable = true;
            lifecycle =
              config.aos.services."polkit.polkit".lifecycle
              // {
                start = [
                  {
                    executable = {
                      path = "${package}/bin/dbus-daemon";
                      arguments = [];
                    };
                    ignore_failure = false;
                  }
                ];
              };
          };
          aos.abilities = {
            serviceManagement.operations.realize.handler.program = package;
            configuration.operations.file.handler.program = package;
            identity.operations.group.handler.program = package;
            identity.operations.principal.handler.program = package;
          };
        };
      })
    ];
  };
  nodes = builtins.attrValues evaluated.config.aos.activation.graph.nodes;
  select = operation: effect: builtins.head (builtins.filter (node: builtins.elem operation node.identity && builtins.elem effect node.identity) nodes);
  sudo = select "privilegedExecutable" "sudo";
  polkit = select "realize" "polkit.polkit";
  selinux = select "realize" "selinux.selinux-policy-load";
  verifier = select "realize" "attestationVerifier";
  quote = select "realize" "package-attestation-quote.aos-attest";
in {
  verifierRetainsIsolation = verifier.input.isolation.network == "none" && verifier.input.identity.ephemeral;
  verifierRetainsOutputPath = builtins.elem "/var/lib/aos-attestation-verifier/result.json" (builtins.head verifier.input.lifecycle.start).executable.arguments;
  quoteWaitsForCommittedActivation = quote.input.dependencies.requires == ["aos-activate.service" "package-profile-convergence.service" "aos-image-boot-commit.service"] && quote.input.auto_start == false && quote.input.activation_owner == "manager" && quote.input.dependencies.wanted_by == ["multi-user.target"];
  sudoWaitsForSudoers = builtins.length sudo.dependencies == 1;
  polkitRegistersRetainedBusPaths = evaluated.config.aos.dbus.activationDirectories == ["${package}/share/dbus-1/system-services"];
  polkitPreservesIdentity = polkit.input.identity.ephemeral == false;
  polkitPreservesIsolation = polkit.input.isolation.network == "none";
  polkitWaitsForRulesAndBus = builtins.length polkit.dependencies >= 4;
  selinuxRetainsPolicyCondition = (builtins.head selinux.input.conditions.all).kind == "mandatory-access-control";
  selinuxRetainsPolicyPath = (builtins.head selinux.input.lifecycle.start).executable.path == "${package}/libexec/aos-selinux-load-policy";
}
