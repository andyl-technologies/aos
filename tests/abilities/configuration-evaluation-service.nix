##! Native host registry refresh and measured image finalization policy.
{
  lib,
  pkgs,
}: let
  payload = import ../effects/_fixture-payload.nix;
  package = {
    type = "derivation";
    outPath = payload "aos";
    outputs = {
      apm = payload "apm";
      packageRuntime = payload "runtime";
    };
  };
  key = builtins.toFile "pcr.pem" "fixture-public-key";
  evaluate = enabled: measured: stage:
    lib.evalModules {
      inherit lib;
      specialArgs = {
        inherit package;
        dependencies.nix = package;
      };
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
        ../../pkgs/tools/aos/_abilities/runtime-layout.nix
        ../../pkgs/tools/aos/_abilities/configuration-evaluation.nix
        ../../pkgs/tools/aos/_abilities/control-plane/module.nix
        {
          options.aos.boot = {
            stage = lib.mkOption {
              type = lib.types.enum ["host" "initrd"];
              default = stage;
            };
            imageEvidenceExecutable = lib.mkOption {
              type = lib.types.str;
              default = "${package.outPath}/bin/aos-image-evidence";
            };
            preparationExecutable = lib.mkOption {
              type = lib.types.str;
              default = "${package.outPath}/bin/aos-boot-preparations";
            };
          };
          config.aos.config.unitGraph.enable = true;
          config.aos.packageRuntime.configurationEvaluation = {
            enable = enabled;
            measuredBoot = measured;
            pcrPublicKey =
              if measured
              then key
              else null;
          };
        }
      ];
    };
  enabled = (evaluate true true "host").config;
  disabled = (evaluate false true "host").config;
  initrd = (evaluate true true "initrd").config;
  unmeasured = (evaluate true false "host").config;
  commit = enabled.aos.services."configuration-evaluation.image-boot-commit";
  command = (builtins.head commit.lifecycle.start).executable;
  registry = enabled.aos.services."configuration-evaluation.registry-synchronization";
  registryDirectory = builtins.head registry.directories.managed;
  activation = configuration: configuration.aos.services."control-plane.aos-activate";
  retryTarget = "${commit.manager_identity.name}.service";
  configured = modules:
    ((evaluate true true "host").extendModules {inherit modules;}).config;
  commitDisabled = configured [
    {aos.services."configuration-evaluation.image-boot-commit".enable = lib.mkForce false;}
  ];
  graphDisabled = configured [
    {aos.config.unitGraph.enable = lib.mkForce false;}
  ];
  activationDisabled = configured [
    {aos.services."control-plane.aos-activate".enable = lib.mkForce false;}
  ];
  renamedCommit = configured [
    {aos.services."configuration-evaluation.image-boot-commit".manager_identity.name = lib.mkForce "renamed-boot-commit";}
  ];
  composed = (evaluate true true "host").extendModules {
    modules = [
      ../../pkgs/boot/_aos-boot-storage/module.nix
      {
        options.aos.filesystems.espDevice = lib.mkOption {
          type = lib.types.str;
        };
      }
    ];
  };
  projected = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit lib pkgs;
    config = composed.config;
  };
  projectedMount = projected."boot-storage.aos-mount-esp";
  projectedCommit = projected."configuration-evaluation.image-boot-commit";
  mountUnit = "${projectedMount.manager_identity.name}.service";
in {
  nativeServicesEnabled = registry.enable && commit.enable;
  disabledServicesAbsent = !disabled.aos.services."configuration-evaluation.registry-synchronization".enable && !disabled.aos.services."configuration-evaluation.image-boot-commit".enable;
  initrdOmitsHostFinalization = !initrd.aos.services."configuration-evaluation.image-boot-commit".enable;
  authenticatedMeasurementRequired = command.arguments == ["commit" "--require-attestation-quote" "--image-evidence-executable" "${package.outPath}/bin/aos-image-evidence" "--pcr-public-key" key];
  unmeasuredCommitRetained = (builtins.head unmeasured.aos.services."configuration-evaluation.image-boot-commit".lifecycle.start).executable.arguments == ["commit"];
  finalizationWaitsForActivation = commit.dependencies.requires == ["aos-mount-esp.service" "aos-activate.service"] && commit.dependencies.before == ["multi-user.target"];
  activationRetryPullsFinalization =
    (activation enabled).dependencies.wants
    == ["aos-registry-sync.service" retryTarget];
  inactiveFinalizationOmitsRetryDependency =
    builtins.all
    (configuration: (activation configuration).dependencies.wants == ["aos-registry-sync.service"])
    [disabled initrd commitDisabled graphDisabled activationDisabled];
  retryDependencyPreservesOrdering =
    builtins.elem "aos-activate.service" commit.dependencies.after
    && builtins.elem "aos-activate.service" commit.dependencies.requires
    && !(builtins.elem retryTarget (activation enabled).dependencies.after)
    && !(builtins.elem "aos-activate.service" commit.dependencies.before)
    && commit.lifecycle.remain_after_exit
    && commit.lifecycle.restart == "never";
  retryTargetUsesEffectiveManagerIdentity =
    (activation renamedCommit).dependencies.wants
    == ["aos-registry-sync.service" "renamed-boot-commit.service"];
  finalizationRequiresProjectedEspMount =
    projectedMount.enabled
    && projectedMount.activation_owner == "image"
    && mountUnit == "aos-mount-esp.service"
    && builtins.elem mountUnit projectedCommit.dependencies.requires
    && builtins.elem mountUnit projectedCommit.dependencies.after;
  firmwareFinalizationConditionRetained = builtins.map (condition: condition.path) commit.conditions.all == ["/sys/firmware/efi"];
  registryUsesAdmittedExecutable =
    (builtins.head registry.lifecycle.start).executable
    == {
      path = "${package.outputs.apm}/bin/apm";
      arguments = ["update" "--system"];
    };
  registryBootstrapOwnsStateDirectory =
    registry.activationOwner
    == "image"
    && !registry.autoStart
    && registryDirectory.path == "apm"
    && registryDirectory.purpose == "state"
    && registryDirectory.retention == "persistent";
  registryStateHasOneBootstrapOwner =
    map (directory: directory.path) registry.directories.managed
    == ["apm" "apm/config" "apm/config/registries.d"]
    && builtins.all (directory:
      directory.mode
      == "0755"
      && directory.purpose == "state"
      && directory.retention == "persistent"
      && directory.owner == "root"
      && directory.group == "root")
    registry.directories.managed
    && builtins.all (directory: !lib.hasPrefix "/var/lib/apm" directory.path) (builtins.attrValues enabled.aos.directories)
    && registry.isolation.host_paths == [];
}
