##! Fixed-point checks for the package-owned boot configuration evaluator.
{
  lib,
  pkgs,
}: let
  evaluate = enabled: measuredBoot: pcrPublicKey:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "test";
            key = "configuration-evaluation";
            stage = "host";
          };
          aos.packageRuntime.configurationEvaluation = {
            enable = enabled;
            baseLib = "/aos-toplevel/base-lib";
            moduleAbi = 7;
            desired = "/etc/aos/packages.d/desired.toml";
            manifest = "/run/aos/manifest.json";
            evalRoot = "/run/aos-eval";
            inherit measuredBoot pcrPublicKey;
          };
        }
      ];
      packageModules = builtins.map lib.abilities.authenticatedPackageModuleRecordFor [
        pkgs.aos
        pkgs.aos-nix-store-provider
        pkgs.systemd
      ];
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
  storeView = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  storeViewLocator = lib.abilities.canonicalJsonOf {
    type = storeView.locatorType;
    value = resultOf "aos:package-store-read-view" "locator";
    maxBytes = 4096;
  };
  lifecycle = requests."aos:configuration-evaluation-lifecycle".parameters;
  registryLifecycle = requests."aos:registry-synchronization-lifecycle".parameters;
  dependencies = requests."aos:configuration-evaluation-dependencies".parameters;
  bootCommitLifecycle = requests."aos:image-boot-commit-lifecycle".parameters;
  bootCommitDependencies = requests."aos:image-boot-commit-dependencies".parameters;
  measurementLifecycle = requests."systemd:image-measurement-index-lifecycle".parameters;
  measurementDependencies = requests."systemd:image-measurement-index-dependencies".parameters;
in
  assert !(disabled.config.aos.abilities.requests ? "aos:configuration-evaluation-lifecycle");
  assert !disabled.config.aos.services."configuration-evaluation.configuration-evaluation".enable;
  assert enabled.config.aos.services."configuration-evaluation.configuration-evaluation".enable;
  assert enabled.config.aos.services."configuration-evaluation.registry-synchronization".enable;
  assert enabled.config.aos.services."configuration-evaluation.image-boot-commit".enable;
  assert !(unmeasured.config.aos.abilities.requests ? "systemd:image-measurement-index-lifecycle");
  assert !unmeasured.config.aos.services."systemd.image-measurement-index".enable;
  assert enabled.config.aos.services."systemd.image-measurement-index".enable;
  assert !missingMeasurementKey.success;
  assert lifecycle.service == "configuration-evaluation";
  assert registryLifecycle.service == "registry-synchronization";
  assert requests."aos:package-store-read-view".parameters == {scope = "boot-image";};
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
          "--store-view"
          storeViewLocator
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
        ];
      };
      ignore_failure = false;
    }
  ];
  assert dependencies.prerequisites
  == [
    (resultOf "aos:nix-store-database" "resource")
    (resultOf "aos:package-store-read-view" "resource")
  ];
  assert dependencies.after
  == [
    (resultOf "aos:host-stage-received" "resource")
    (resultOf "aos:local-filesystems" "resource")
    (resultOf "aos:network-readiness" "resource")
    (resultOf "aos:registry-synchronization-lifecycle" "resource")
  ];
  assert dependencies.requires
  == [
    (resultOf "aos:host-stage-received" "resource")
    (resultOf "aos:local-filesystems" "resource")
  ];
  assert dependencies.wanted_by
  == [(resultOf "aos:user-sessions-ready" "resource")];
  assert dependencies.wants
  == [
    (resultOf "aos:network-readiness" "resource")
    (resultOf "aos:registry-synchronization-lifecycle" "resource")
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
    (resultOf "aos:esp-ready" "resource")
    (resultOf "aos:aos-graph-compile-lifecycle" "resource")
    (resultOf "aos:aos-activate-lifecycle" "resource")
    (resultOf "aos:aos-config" "resource")
  ];
  assert bootCommitDependencies.requires
  == [
    (resultOf "aos:esp-ready" "resource")
    (resultOf "aos:aos-graph-compile-lifecycle" "resource")
  ];
  assert bootCommitDependencies.before
  == [(resultOf "aos:multi-user" "resource")];
  assert bootCommitDependencies.wanted_by
  == [(resultOf "aos:multi-user" "resource")];
  assert measurementLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "systemd";
        };
        entry_point = "libexec/aos-systemd-provider";
        arguments = ["measurement-index" "--pcr-public-key" pcrPublicKey];
      };
      ignore_failure = false;
    }
  ];
  assert measurementDependencies.after
  == [
    (resultOf "systemd:measurement-esp-ready" "resource")
    (resultOf "systemd:measurement-local-filesystems" "resource")
    (resultOf "systemd:measurement-runtime-entries" "resource")
  ];
  assert measurementDependencies.before
  == [(resultOf "systemd:measurement-multi-user" "resource")];
  assert measurementDependencies.requires == measurementDependencies.after; true
