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
  quoteLifecycle = requests."aos:aos-attest-lifecycle".parameters;
in
  assert !(disabledRequests ? "aos:package-profile-specification");
  assert disabledRequests ? "aos:package-profile-convergence-lifecycle";
  assert disabledRequests ? "aos:aos-attest-lifecycle";
  assert initrd.config.aos.abilities.requests == {};
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
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "bin/aos-package-runtime";
        arguments = ["__attest-service"];
      };
      ignore_failure = false;
    }
  ];
  assert requests."aos:aos-attest-dependencies".parameters.prerequisites
  == [(resultOf "aos:package-profile-convergence-lifecycle" "service-resource")];
  assert !(enabled.config ? systemd); true
