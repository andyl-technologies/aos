##! Verifies enabled native security consumers preserve resource ordering and policy.
{pkgs}: let
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
  projectSudo = operator:
    lib.evalPackageModules {
      scope = ["profile" "system"];
      packages = [pkgs.sudo];
      packageImportRoots.${builtins.unsafeDiscardStringContext (toString pkgs.sudo.module)} = toString ../../pkgs/security/_sudo;
      operatorModules = [{aos.security.sudo.enable = true;} operator];
    };
  sudoPolicy = projection: projection.config.aos.abilities.configuration.operations.file.effects.sudoers.input.content;
  nativeSudo = projectSudo {};
  userPathSudo = projectSudo ({lib, ...}: {
    options.environment.sessionVariables = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
    };
    config.environment.sessionVariables.PATH = "/var/lib/profiles/per-user/alice/current/bin";
  });
  imageSecurePath = "/run/wrappers/bin:/image/package/bin:/image/package/sbin";
  imageSudo = projectSudo ({lib, ...}: {
    options.system.build.systemPath = lib.mkOption {type = lib.types.str;};
    config.system.build.systemPath = imageSecurePath;
  });
  sshProjection = lib.evalPackageModules {
    scope = ["profile" "system"];
    packages = [pkgs.openssh];
    packageImportRoots.${builtins.unsafeDiscardStringContext (toString pkgs.openssh.module)} = toString ../../pkgs/networking/_openssh;
    operatorModules = [{aos.services.ssh.enable = true;}];
  };
  developmentConfiguration = enabled:
    (lib.evalModules {
      inherit lib;
      specialArgs = {inherit pkgs;};
      modules = [
        ../../modules/profiles/development.nix
        {
          options = {
            environment = lib.mkOption {type = lib.types.attrsOf lib.types.anything;};
            system = lib.mkOption {type = lib.types.attrsOf lib.types.anything;};
            aos.security = lib.mkOption {type = lib.types.attrsOf lib.types.anything;};
            aos.activation.stages.host.configuration = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
          };
          config.aos.profiles.development.enable = enabled;
        }
      ];
    }).config.aos.activation.stages.host.configuration;
  pingEffects = enabled:
    (lib.evalPackageModules {
      scope = ["profile" "system"];
      packages = [pkgs.inetutils];
      packageImportRoots.${builtins.unsafeDiscardStringContext (toString pkgs.inetutils.module)} = toString ../../pkgs/networking/_inetutils;
      # Read the authored leaf without realizing its retained store copy.
      operatorModules = map (source:
        assert source
        == builtins.path {
          path = ../../modules/profiles/_development-enable.nix;
          name = "aos-development-policy.nix";
        };
          ../../modules/profiles/_development-enable.nix)
      (developmentConfiguration enabled);
    }).config.aos.abilities.filesystem.operations.privilegedExecutable.effects;
  developmentPing = pingEffects true;
  originalPingMetadata = name: let
    input = developmentPing."inetutils-${name}".input;
  in
    input.name == name && input.source == "${pkgs.inetutils}/bin/${name}" && input.mode == "4755" && input.owner == "root" && input.group == "root";
in {
  polkitPreservesFatalSyscallFilter = polkit.input.policy.hardening.operation_profile == "system-service" && polkit.input.policy.hardening.denied_operation_action == "kill-process";
  verifierRetainsIsolation = verifier.input.isolation.network == "none" && verifier.input.identity.ephemeral;
  verifierRetainsOutputPath = builtins.elem "/var/lib/aos-attestation-verifier/result.json" (builtins.head verifier.input.lifecycle.start).executable.arguments;
  quoteWaitsForCommittedActivation = quote.input.dependencies.requires == ["aos-activate.service" "package-profile-convergence.service" "aos-image-boot-commit.service"] && quote.input.auto_start == false && quote.input.activation_owner == "manager" && quote.input.dependencies.wanted_by == ["multi-user.target"];
  sudoWaitsForSudoers = builtins.length sudo.dependencies == 1;
  sudoFollowsActiveSystemProfiles = lib.hasInfix ''Defaults secure_path="/run/wrappers/bin:/var/lib/profiles/system-packages/current/bin:/var/lib/profiles/system-packages/current/sbin:/var/lib/profiles/system/current/bin:/var/lib/profiles/system/current/sbin"'' (sudoPolicy nativeSudo);
  sudoExcludesUserProfilePaths = sudoPolicy userPathSudo == sudoPolicy nativeSudo;
  sudoPreservesImageSystemPath = lib.hasInfix ''Defaults secure_path="${imageSecurePath}"'' (sudoPolicy imageSudo);
  sshStableManagerIdentities = sshProjection.config.aos.abilities.serviceManagement.operations.realize.effects.ssh.input.service == "sshd" && sshProjection.config.aos.abilities.serviceManagement.operations.realize.effects."ssh.sshd-keygen".input.service == "sshd-keygen";
  sshPreservesPublicHostKeyDirectoryAccess = sshProjection.config.aos.abilities.filesystem.operations.directory.effects.ssh-host-keys.input.mode == "0755";
  developmentRetainsOriginalPingWrappers = builtins.all originalPingMetadata ["ping" "ping6"];
  standardProfileDoesNotEnablePrivilegedPing = pingEffects false == {};
  polkitRegistersRetainedBusPaths = evaluated.config.aos.dbus.activationDirectories == ["${package}/share/dbus-1/system-services"];
  polkitPreservesIdentity = polkit.input.identity.ephemeral == false;
  polkitPreservesIsolation = polkit.input.isolation.network == "none";
  polkitWaitsForRulesAndBus = builtins.length polkit.dependencies >= 4;
  selinuxRetainsPolicyCondition = (builtins.head selinux.input.conditions.all).kind == "mandatory-access-control";
  selinuxRetainsPolicyPath = (builtins.head selinux.input.lifecycle.start).executable.path == "${package}/libexec/aos-selinux-load-policy";
}
