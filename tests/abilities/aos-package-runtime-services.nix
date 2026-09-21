##! Fixed-point checks for the AOS package-runtime service owners.
{
  lib,
  pkgs,
}: let
  aosPackageModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.aos;
  systemdPackageModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd;
  packageProfileProviderModule =
    aosPackageModule
    // {
      module = "${pkgs.aos.module}/package-profile-readiness-provider.nix";
    };
  evaluate = {
    enabled,
    stage ? "host",
    providerModules ? [],
  }:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "aos-package-runtime";
            inherit stage;
          };
          aos.packageRuntime.packageProfile = {
            enable = enabled;
            desiredText = ''
              packages = ["nginx"]
            '';
          };
          aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = enabled;
        }
      ];
      packageModules = [aosPackageModule systemdPackageModule];
      selectedProviderModules = providerModules;
    };
  disabled = evaluate {enabled = false;};
  enabled = evaluate {enabled = true;};
  providerEnabled = evaluate {
    enabled = true;
    providerModules = [packageProfileProviderModule];
  };
  initrd = evaluate {
    enabled = true;
    stage = "initrd";
  };
  disabledRequests = disabled.config.aos.abilities.requests;
  requests = enabled.config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  profileLifecycle = requests."aos:package-profile-convergence-lifecycle".parameters;
  quoteLifecycle = requests."aos:aos-attest-lifecycle".parameters;
  snapshotImplementation = enabled.config.aos.abilities.implementations."aos:synchronized-registry-snapshot";
  providedReadinessImplementation =
    providerEnabled.config.aos.abilities.implementations."aos:package-profile-readiness";
in
  assert !(disabledRequests ? "aos:package-profile-specification");
  assert !(disabledRequests ? "aos:package-profile-readiness");
  assert disabledRequests ? "aos:package-profile-convergence-lifecycle";
  assert disabledRequests ? "aos:aos-attest-lifecycle";
  assert !(initrd.config.aos.abilities.requests ? "aos:aos-attest-lifecycle");
  assert !(initrd.config.aos.abilities.requests ? "aos:package-profile-readiness");
  assert requests."aos:package-profile-readiness".parameters == "system-profile";
  assert enabled.config.aos.abilities.implementations."aos:package-profile-readiness".providerModule.path
  == "package-profile-readiness-provider.nix";
  assert builtins.isFunction providedReadinessImplementation.provide;
  assert providedReadinessImplementation.description
  == "Publishes package-profile convergence through the package-owned lifecycle resource.";
  assert !(providerEnabled.config.aos.abilities.implementations ? "aos:aos:package-profile-readiness");
  assert enabled.config.aos.abilities.instances."aos:synchronized-registry-snapshot".implementation
  == "aos:synchronized-registry-snapshot";
  assert !(initrd.config.aos.abilities.instances ? "aos:synchronized-registry-snapshot");
  assert snapshotImplementation.providerModule == null;
  assert snapshotImplementation.handlerDescriptor.entryPoint == "libexec/aos-registry-snapshot-provider";
  assert requests."aos:package-profile-specification".parameters.source.content
  == ''
    packages = ["nginx"]
  '';
  assert profileLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "apm";
        };
        entry_point = "bin/apm";
        arguments = [
          "install"
          "--system"
          "--from"
          (resultOf "aos:package-profile-specification" "planned-path")
          "--yes"
        ];
      };
      ignore_failure = false;
    }
  ];
  assert requests."aos:package-profile-convergence-dependencies".parameters.prerequisites
  == [
    (resultOf "aos:configuration-evaluation-lifecycle" "resource")
    (resultOf "aos:package-profile-specification" "resource")
  ];
  assert quoteLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "libexec/aos-package-attestation-provider";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert requests."aos:aos-attest-dependencies".parameters.prerequisites
  == [(resultOf "aos:package-profile-readiness" "resource")];
  assert !(enabled.config ? systemd); true
