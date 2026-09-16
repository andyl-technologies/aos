##! Fixed-point checks for the AOS package-runtime service owners.
{
  lib,
  pkgs,
}: let
  evaluate = {
    enabled,
    stage ? "host",
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
      packageModules = [
        {
          name = "aos";
          version = pkgs.aos.version;
          module = pkgs.aos.module + "/module.nix";
        }
        {
          name = "systemd";
          version = pkgs.systemd.version;
          module = pkgs.systemd.module + "/module.nix";
        }
      ];
    };
  disabled = evaluate {enabled = false;};
  enabled = evaluate {enabled = true;};
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
  quoteLifecycle = requests."systemd:aos-attest-lifecycle".parameters;
  snapshotImplementation = enabled.config.aos.abilities.implementations."aos:synchronized-registry-snapshot";
in
  assert !(disabledRequests ? "aos:package-profile-specification");
  assert disabledRequests ? "aos:package-profile-convergence-lifecycle";
  assert disabledRequests ? "systemd:aos-attest-lifecycle";
  assert !(initrd.config.aos.abilities.requests ? "systemd:aos-attest-lifecycle");
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
    (resultOf "aos:configuration-evaluation-lifecycle" "service-resource")
    (resultOf "aos:package-profile-specification" "retained-resource")
  ];
  assert quoteLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos-systemd-provider";
        };
        entry_point = "bin/aos-systemd-attestation-provider";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert requests."systemd:aos-attest-dependencies".parameters.prerequisites
  == [(resultOf "aos:package-profile-convergence-lifecycle" "service-resource")];
  assert !(enabled.config ? systemd); true
