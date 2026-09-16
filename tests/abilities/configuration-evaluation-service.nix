##! Fixed-point checks for the package-owned boot configuration evaluator.
{
  lib,
  pkgs,
}: let
  evaluate = enabled: measuredBoot: pcrPublicKey:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "configuration-evaluation";
            stage = "host";
          };
          aos.packageRuntime.configurationEvaluation = {
            enable = enabled;
            hostNix = "/run/aos-metadata/host.nix";
            baseLib = "/aos-toplevel/base-lib";
            moduleAbi = 7;
            desired = "/etc/aos/packages.d/desired.toml";
            manifest = "/run/aos/manifest.json";
            evalRoot = "/run/aos-eval";
            provisioningState = "/var/lib/aos-provisioning";
            imageVersion = "2026.09";
            inherit measuredBoot pcrPublicKey;
          };
        }
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "aos";
          version = pkgs.aos.version;
          module = pkgs.aos.module + "/module.nix";
        }
        {
          name = "aos-nix-store-provider";
          version = pkgs.aos-nix-store-provider.version;
          module = pkgs.aos-nix-store-provider.module + "/module.nix";
        }
      ]));

    };
  pcrPublicKey = "/nix/store/00000000000000000000000000000000-aos-pcr-pubkey/pcr.pem";
  disabled = evaluate false true pcrPublicKey;
  unmeasured = evaluate true false null;
  missingMeasurementKey = builtins.tryEval (builtins.deepSeq (evaluate true true null).config.aos.abilities.requests true);
  enabled = evaluate true true pcrPublicKey;
  requests = enabled.config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  lifecycle = requests."aos:configuration-evaluation-lifecycle".parameters;
  registryLifecycle = requests."aos:registry-synchronization-lifecycle".parameters;
  dependencies = requests."aos:configuration-evaluation-dependencies".parameters;
  bootCommitLifecycle = requests."aos:image-boot-commit-lifecycle".parameters;
  bootCommitDependencies = requests."aos:image-boot-commit-dependencies".parameters;
  fallbackLifecycle = requests."aos:image-rollout-fallback-lifecycle".parameters;
  measurementLifecycle = requests."aos:image-measurement-index-lifecycle".parameters;
  measurementDependencies = requests."aos:image-measurement-index-dependencies".parameters;
in
  assert !(disabled.config.aos.abilities.requests ? "aos:configuration-evaluation-lifecycle");
  assert !(unmeasured.config.aos.abilities.requests ? "aos:image-measurement-index-lifecycle");
  assert !missingMeasurementKey.success;
  assert lifecycle.service == "configuration-evaluation";
  assert registryLifecycle.service == "registry-synchronization";
  assert registryLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "apm";
        };
        entry_point = "bin/apm";
        arguments = ["update" "--system"];
      };
      ignore_failure = false;
    }
  ];
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "bin/aos-package-runtime";
        arguments = [
          "__eval-service"
          "--host-nix"
          "/run/aos-metadata/host.nix"
          "--base-lib"
          "/aos-toplevel/base-lib"
          "--module-abi"
          "7"
          "--desired"
          "/etc/aos/packages.d/desired.toml"
          "--out"
          "/run/aos/manifest.json"
          "--eval-root"
          "/run/aos-eval"
          "--provisioning-state"
          "/var/lib/aos-provisioning"
          "--image-version"
          "2026.09"
        ];
      };
      ignore_failure = false;
    }
  ];
  assert dependencies.prerequisites
  == [(resultOf "aos:nix-store-database" "readiness-resource")];
  assert dependencies.after
  == [
    (resultOf "aos:local-filesystems" "readiness-resource")
    (resultOf "aos:network-readiness" "readiness-resource")
    (resultOf "aos:aos-credential-recovery-lifecycle" "service-resource")
    (resultOf "aos:registry-synchronization-lifecycle" "service-resource")
  ];
  assert dependencies.requires
  == [
    (resultOf "aos:local-filesystems" "readiness-resource")
    (resultOf "aos:aos-credential-recovery-lifecycle" "service-resource")
  ];
  assert dependencies.wanted_by
  == [(resultOf "aos:user-sessions-ready" "readiness-resource")];
  assert dependencies.wants
  == [
    (resultOf "aos:network-readiness" "readiness-resource")
    (resultOf "aos:registry-synchronization-lifecycle" "service-resource")
  ];
  assert requests."aos:configuration-evaluation-manager_identity".parameters.name == "aos-eval";
  assert bootCommitLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "libexec/aos-image-rollout-boot";
        arguments = ["commit" "--require-attestation-quote"];
      };
      ignore_failure = false;
    }
  ];
  assert bootCommitDependencies.after
  == [
    (resultOf "aos-boot-storage:aos-mount-esp-lifecycle" "service-resource")
    (resultOf "aos:aos-graph-compile-lifecycle" "service-resource")
    (resultOf "aos:aos-activate-lifecycle" "service-resource")
    (resultOf "aos:aos-config" "activation-resource")
  ];
  assert bootCommitDependencies.requires
  == [
    (resultOf "aos-boot-storage:aos-mount-esp-lifecycle" "service-resource")
    (resultOf "aos:aos-graph-compile-lifecycle" "service-resource")
  ];
  assert bootCommitDependencies.before
  == [(resultOf "aos:multi-user" "readiness-resource")];
  assert bootCommitDependencies.wanted_by
  == [(resultOf "aos:multi-user" "readiness-resource")];
  assert requests."aos:image-boot-commit-failure_policy".parameters.handlers
  == [(resultOf "aos:image-rollout-fallback-lifecycle" "service-resource")];
  assert fallbackLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "libexec/aos-image-rollout-boot";
        arguments = ["fallback"];
      };
      ignore_failure = false;
    }
  ];
  assert !fallbackLifecycle.enabled;
  assert measurementLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "libexec/aos-image-rollout-boot";
        arguments = ["measurement-index" "--pcr-public-key" pcrPublicKey];
      };
      ignore_failure = false;
    }
  ];
  assert measurementDependencies.after
  == [
    (resultOf "aos-boot-storage:aos-mount-esp-lifecycle" "service-resource")
    (resultOf "aos:local-filesystems" "readiness-resource")
    (resultOf "aos:runtime-entry-population" "lifecycle-resource")
  ];
  assert measurementDependencies.before
  == [
    (resultOf "aos:configuration-evaluation-lifecycle" "service-resource")
    (resultOf "aos:multi-user" "readiness-resource")
  ];
  assert measurementDependencies.requires == measurementDependencies.after;
  assert !(enabled.config ? systemd); true
