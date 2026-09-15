##! Fixed-point checks for the package-owned boot configuration evaluator.
{
  lib,
  pkgs,
}: let
  evaluate = enabled:
    lib.evalModules {
      inherit lib;
      modules = [
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
          };
        }
      ];
      packageModules = [
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
      ];
    };
  disabled = evaluate false;
  enabled = evaluate true;
  requests = enabled.config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  lifecycle = requests."aos:configuration-evaluation-lifecycle".parameters;
  registryLifecycle = requests."aos:registry-synchronization-lifecycle".parameters;
  dependencies = requests."aos:configuration-evaluation-dependencies".parameters;
in
  assert !(disabled.config.aos.abilities.requests ? "aos:configuration-evaluation-lifecycle");
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
  assert !(enabled.config ? systemd); true
