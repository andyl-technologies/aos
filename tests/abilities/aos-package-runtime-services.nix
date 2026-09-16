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
      modules =
        ([
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
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "aos";
          version = pkgs.aos.version;
          module = pkgs.aos.module + "/module.nix";
        }
      ]));

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
  credentialRecoveryLifecycle = requests."aos:aos-credential-recovery-lifecycle".parameters;
  snapshotImplementation = enabled.config.aos.abilities.implementations."aos:synchronized-registry-snapshot";
in
  assert !(disabledRequests ? "aos:package-profile-specification");
  assert disabledRequests ? "aos:package-profile-convergence-lifecycle";
  assert disabledRequests ? "aos:aos-attest-lifecycle";
  assert disabledRequests ? "aos:aos-credential-recovery-lifecycle";
  assert initrd.config.aos.abilities.requests == {};
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
  assert credentialRecoveryLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {
          package = "aos";
          output = "packageRuntime";
        };
        entry_point = "bin/aos-package-runtime";
        arguments = ["recover-credential-transactions"];
      };
      ignore_failure = false;
    }
  ];
  assert requests."aos:aos-credential-recovery-dependencies".parameters == {
    service = "aos-credential-recovery";
    enabled = true;
    prerequisites = [];
    after = [(resultOf "aos:local-filesystems" "readiness-resource")];
    before = [(resultOf "aos:early-system" "readiness-resource")];
    requires = [(resultOf "aos:local-filesystems" "readiness-resource")];
    wants = [];
    requisite = [];
    conflicts = [];
    binds_to = [];
    part_of = [];
    upholds = [];
    required_by = [(resultOf "aos:early-system" "readiness-resource")];
    wanted_by = [];
    required_mounts = [];
    implicit_dependencies = false;
  };
  assert !(enabled.config ? systemd); true
