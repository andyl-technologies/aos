##! Fixed-point checks for the AOS package-runtime service owners.
{
  lib,
  pkgs,
}: let
  evaluate = {stage ? "host"}:
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
  host = evaluate {};
  initrd = evaluate {
    stage = "initrd";
  };
  requests = host.config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  quoteLifecycle = requests."aos:aos-attest-lifecycle".parameters;
  credentialRecoveryLifecycle = requests."aos:aos-credential-recovery-lifecycle".parameters;
  snapshotImplementation = host.config.aos.abilities.implementations."aos:synchronized-registry-snapshot";
in
  assert !(requests ? "aos:package-profile-specification");
  assert !(requests ? "aos:package-profile-convergence-lifecycle");
  assert requests ? "aos:aos-attest-lifecycle";
  assert requests ? "aos:aos-credential-recovery-lifecycle";
  assert initrd.config.aos.abilities.requests == {};
  assert host.config.aos.abilities.instances."aos:synchronized-registry-snapshot".implementation
  == "aos:synchronized-registry-snapshot";
  assert !(initrd.config.aos.abilities.instances ? "aos:synchronized-registry-snapshot");
  assert snapshotImplementation.providerModule == null;
  assert snapshotImplementation.handlerDescriptor.entryPoint == "libexec/aos-registry-snapshot-provider";
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
  == [];
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
  assert !(host.config ? systemd); true
