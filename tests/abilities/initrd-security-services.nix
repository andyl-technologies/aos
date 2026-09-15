##! Package-owned initrd security lifecycle declarations.
{
  lib,
  pkgs,
}: let
  environment = stage: {
    authority = "test";
    key = "initrd-security-services";
    inherit stage;
  };
  packageModule = package: {
    name = package.pname;
    inherit (package) version;
    module = package.module + "/module.nix";
  };
  evaluate = stage: modules: packageModules:
    lib.evalModules {
      inherit lib packageModules;
      modules =
        [
          lib.abilities.module
          {aos.abilities.environment = environment stage;}
        ]
        ++ modules;
    };
  disabled = evaluate "host" [] [
    (packageModule pkgs.aos-verity-root-guard)
    (packageModule pkgs.aos-var-policy-migrate)
  ];
  configured =
    evaluate "initrd" [
      {
        aos.security = {
          verityRootVerification.enable = true;
          measuredVar = {
            enable = true;
            pcrPublicKey = "/nix/store/public/pcr.pem";
            signedPcrs = "11";
            pinnedPcrs = "7+12";
            recoveryKeyPath = "/run/aos-var-recovery.key";
            requireVerity = true;
          };
        };
      }
    ] [
      (packageModule pkgs.aos-verity-root-guard)
      (packageModule pkgs.aos-var-policy-migrate)
    ];
  requests = configured.config.aos.abilities.requests;
  request = package: name: requests."${package}:${name}".parameters;
  output = requestName: outputName: {
    _type = "aos-request-output-reference";
    request = requestName;
    output = outputName;
  };
  guardDependencies = request "aos-verity-root-guard" "aos-verity-root-verify-dependencies";
  guardFailure = request "aos-verity-root-guard" "aos-verity-root-verify-failure_policy";
  measuredVarLifecycle = request "aos-var-policy-migrate" "aos-var-crypt-lifecycle";
  measuredVarDependencies = request "aos-var-policy-migrate" "aos-var-crypt-dependencies";
  measuredVarCondition = request "aos-var-policy-migrate" "aos-var-crypt-conditions";
in
  assert disabled.config.aos.abilities.requests == {};
  assert builtins.attrNames configured.config.aos.abilities.instances
  == [
    "aos-var-policy-migrate:measured-var"
    "aos-verity-root-guard:verity-root-verification"
  ];
  assert (builtins.head measuredVarLifecycle.start).executable.entry_point == "bin/aos-var-crypt";
  assert (builtins.head measuredVarLifecycle.start).executable.arguments
  == [
    "/nix/store/public/pcr.pem"
    "11"
    "7+12"
    "/run/aos-var-recovery.key"
  ];
  assert measuredVarDependencies.after
  == [
    (output "aos-var-policy-migrate:boot-identity" "readiness-resource")
    (output "aos-var-policy-migrate:partition-layout" "readiness-resource")
    (output "aos-var-policy-migrate:device-events" "readiness-resource")
    (output "aos-var-policy-migrate:verity-root" "readiness-resource")
  ];
  assert measuredVarDependencies.requires
  == [
    (output "aos-var-policy-migrate:boot-identity" "readiness-resource")
    (output "aos-var-policy-migrate:verity-root" "readiness-resource")
  ];
  assert measuredVarDependencies.implicit_dependencies;
  assert measuredVarCondition.all
  == [
    {
      kind = "kernel-argument";
      argument = "aos.recovery=1";
      negated = true;
    }
  ];
  assert (request "aos-var-policy-migrate" "boot-identity").milestone
  == "boot-identity-validated";
  assert (request "aos-var-policy-migrate" "partition-layout").milestone
  == "partition-layout-ready";
  assert (request "aos-var-policy-migrate" "device-events").milestone == "device-settle";
  assert (request "aos-var-policy-migrate" "initrd-filesystems").milestone
  == "initrd-filesystems";
  assert (request "aos-var-policy-migrate" "persistent-state").milestone == "var";
  assert (request "aos-var-policy-migrate" "verity-root").milestone
  == "verity-root-verified";
  assert guardDependencies.required_by
  == [
    (output "aos-verity-root-guard:persistent-state" "readiness-resource")
    (output "aos-verity-root-guard:initrd-filesystems" "readiness-resource")
  ];
  assert guardDependencies.after
  == [
    (output "aos-verity-root-guard:boot-identity" "readiness-resource")
    (output "aos-verity-root-guard:partition-layout" "readiness-resource")
    (output "aos-verity-root-guard:device-events" "readiness-resource")
  ];
  assert guardFailure
  == {
    service = "aos-verity-root-verify";
    enabled = true;
    handlers = [(output "aos-verity-root-guard:integrity-failure" "readiness-resource")];
    dispatch = "isolate-active-goal";
  }; true
