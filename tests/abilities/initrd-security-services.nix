##! Package-owned initrd security lifecycle declarations.
{
  lib,
  mkSystem,
  pkgs,
}: let
  milestones = lib.abilities.interfaces.serviceManagement.milestones;
  environment = stage: {
    authority = "test";
    key = "initrd-security-services";
    inherit stage;
  };
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor;
  evaluate = stage: modules: packageModules:
    lib.evalModules {
      inherit lib packageModules;
      modules =
        [
          lib.abilities.module
          ../../modules/base/_kernel-parameter-contributions.nix
          {aos.abilities.environment = environment stage;}
        ]
        ++ modules;
    };
  disabled = evaluate "host" [] [
    (packageModule pkgs.aos-boot-identity)
    (packageModule pkgs.aos-verity-root-guard)
    (packageModule pkgs.aos-systemd-var-policy)
    (packageModule pkgs.systemd)
  ];
  configured =
    evaluate "initrd" [
      {
        aos.security = {
          bootIdentityServices.enable = true;
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
      (packageModule pkgs.aos-boot-identity)
      (packageModule pkgs.aos-verity-root-guard)
      (packageModule pkgs.aos-systemd-var-policy)
      (packageModule pkgs.systemd)
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
  measuredVarLifecycle = request "aos-systemd-var-policy" "aos-var-crypt-lifecycle";
  measuredVarDependencies = request "aos-systemd-var-policy" "aos-var-crypt-dependencies";
  measuredVarCondition = request "aos-systemd-var-policy" "aos-var-crypt-conditions";
  identityGuardDependencies = request "aos-boot-identity" "aos-boot-identity-guard-dependencies";
  identityGuardFailure = request "aos-boot-identity" "aos-boot-identity-guard-failure_policy";
  systemdVerityDependencies = request "systemd" "aos-systemd-verity-root-setup-dependencies";
  systemdVerityLifecycle = request "systemd" "aos-systemd-verity-root-setup-lifecycle";
  bootIdentityScript = builtins.readFile ../../pkgs/security/_aos-boot-identity/aos-boot-identity-success.sh;
  bootIdentityModule = builtins.readFile ../../pkgs/security/_aos-boot-identity/module.nix;
  verityVerificationScript = builtins.readFile ../../pkgs/security/_aos-verity-root-guard/aos-verity-root-verify.sh;
  seedProfilesScript = builtins.readFile ../../pkgs/boot/_aos-boot-preparations/aos-seed-profiles.sh;
  managerCommands = ["systemctl" "bootctl" "aos-systemd-veritysetup-generator" "/run/systemd"];
  secureVeritySystem = mkSystem {
    systemName = "initrd-security-intent-test";
    modules = [../../systems/server-verity.nix];
  };
  secureVerityPackages =
    builtins.map
    (package: package.pname)
    secureVeritySystem.config.aos.boot.initrd.packageRoots;
  secureBootModule = builtins.readFile ../../modules/base/secure-boot.nix;
in
  assert builtins.all
  (requestName: !(lib.hasPrefix "aos-systemd-var-policy:" requestName))
  (builtins.attrNames disabled.config.aos.abilities.requests);
  assert builtins.attrNames configured.config.aos.abilities.instances
  == [
    "aos-boot-identity:boot-identity"
    "aos-systemd-var-policy:measured-var"
    "aos-verity-root-guard:verity-root-verification"
    "systemd:systemd-verity-root"
  ];
  assert (builtins.head systemdVerityLifecycle.start).executable.entry_point
  == "libexec/aos-systemd-verity-root-setup";
  assert systemdVerityDependencies.requires
  == [
    (output "systemd:boot-identity" "readiness-resource")
    (output "systemd:device-manager" "readiness-resource")
    (output "systemd:device-events" "readiness-resource")
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
    (output "aos-systemd-var-policy:boot-identity" "readiness-resource")
    (output "aos-systemd-var-policy:initrd-stage" "readiness-resource")
    (output "aos-systemd-var-policy:device-events" "readiness-resource")
    (output "aos-systemd-var-policy:verity-root" "readiness-resource")
  ];
  assert measuredVarDependencies.requires
  == [
    (output "aos-systemd-var-policy:boot-identity" "readiness-resource")
    (output "aos-systemd-var-policy:verity-root" "readiness-resource")
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
  assert (request "aos-systemd-var-policy" "boot-identity").milestone
  == milestones.bootIdentityValidated;
  assert (request "aos-systemd-var-policy" "initrd-stage").milestone
  == milestones.initrdStageExecuted;
  assert (request "aos-systemd-var-policy" "device-events").milestone == milestones.deviceSettle;
  assert (request "aos-systemd-var-policy" "initrd-filesystems").milestone
  == milestones.initrdFilesystems;
  assert (request "aos-systemd-var-policy" "persistent-state").milestone == milestones.var;
  assert (request "aos-systemd-var-policy" "verity-root").milestone
  == milestones.verityRootVerified;
  assert (request "aos-verity-root-guard" "verity-root-mapping").milestone
  == milestones.verityRootMappingReady;
  assert !(requests ? "aos-boot-identity:boot-identity-failure-target");
  assert !(lib.hasInfix "aos.systemd.packaged-unit" bootIdentityModule);
  assert !(lib.hasInfix ''{package = "systemd";}'' bootIdentityModule);
  assert identityGuardDependencies.required_by
  == [(output "aos-boot-identity:initrd-filesystems" "readiness-resource")];
  assert identityGuardFailure.dispatch == "isolate-active-goal";
  assert identityGuardFailure.handlers
  == [(output "aos-boot-identity:integrity-failure" "readiness-resource")];
  assert builtins.elem "systemd" secureVerityPackages;
  assert builtins.elem "aos-systemd-var-policy" secureVerityPackages;
  assert !(lib.hasInfix "pkgs.systemd" secureBootModule);
  assert !(lib.hasInfix "pkgs.aos-systemd-var-policy" secureBootModule);
  assert guardDependencies.required_by
  == [
    (output "aos-verity-root-guard:persistent-state" "readiness-resource")
    (output "aos-verity-root-guard:initrd-filesystems" "readiness-resource")
  ];
  assert guardDependencies.after
  == [
    (output "aos-verity-root-guard:boot-identity" "readiness-resource")
    (output "aos-verity-root-guard:verity-root-mapping" "readiness-resource")
    (output "aos-verity-root-guard:initrd-stage" "readiness-resource")
    (output "aos-verity-root-guard:device-events" "readiness-resource")
  ];
  assert guardFailure
  == {
    service = "aos-verity-root-verify";
    enabled = true;
    handlers = [(output "aos-verity-root-guard:integrity-failure" "readiness-resource")];
    dispatch = "isolate-active-goal";
  };
  assert builtins.all (command: !(lib.hasInfix command bootIdentityScript)) managerCommands;
  assert builtins.all (command: !(lib.hasInfix command verityVerificationScript)) managerCommands;
  assert builtins.all (command: !(lib.hasInfix command seedProfilesScript)) ["systemctl" "bootctl"]; true
