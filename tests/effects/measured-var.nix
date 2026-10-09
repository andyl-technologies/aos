##! Checks native TPM persistent-state ordering and SELinux fixture hardening.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "policy-fixture";
    outPath = import ./_fixture-payload.nix "measured-var";
  };
  evaluate = stage: verity:
    lib.evalModules {
      inherit lib;
      specialArgs = {
        inherit package;
        dependencies.coreutils = package;
      };
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ../../pkgs/system/_aos-systemd-var-policy/module.nix
        ../../tests/fixtures/selinux-base-package/module.nix
        {
          options.aos.boot.stage = lib.mkOption {type = lib.types.enum ["host" "initrd"];};
          config = {
            aos.boot.stage = stage;
            aos.security.measuredVar = {
              enable = true;
              requireVerity = verity;
              pcrPublicKey = "/etc/aos/pcr-public-key.pem";
            };
          };
        }
      ];
    };
  derived =
    (lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ../../pkgs/boot/_aos-boot-storage/options.nix
        ../../pkgs/boot/_aos-boot-storage/measurement-options.nix
        ../../pkgs/system/_aos-systemd-var-policy/module.nix
        {
          options.aos.boot.stage = lib.mkOption {type = lib.types.enum ["host" "initrd"];};
          config = {
            aos.boot.stage = "initrd";
            aos.boot.secureBoot.measuredBoot = {
              enable = true;
              _effectivePcrPublicKey = "${package}/pcr.pem";
              signedPcrs = "11+14";
              pinnedPcrs = "7+12+13";
              recoveryKeyPath = "/run/native-recovery.key";
            };
            aos.security.verity.enable = true;
          };
        }
      ];
    }).config;
  initrd = (evaluate "initrd" true).config;
  normal = (evaluate "initrd" false).config;
  host = (evaluate "host" true).config;
  service = initrd.aos.services."measured-var.aos-var-crypt";
  denial = initrd.aos.services."selinux-base-test.selinux-native-deny";
in {
  portableMeasuredPolicyEnablesUnlock = derived.aos.services."measured-var.aos-var-crypt".enable;
  portableMeasuredPolicyRetainsExactParameters =
    (builtins.head derived.aos.services."measured-var.aos-var-crypt".lifecycle.start).executable.arguments
    == [
      "${package}/pcr.pem"
      "11+14"
      "7+12+13"
      "/run/native-recovery.key"
    ];
  portableVerityPolicyOrdersUnlock = builtins.elem "aos-verity-root-verify.service" derived.aos.services."measured-var.aos-var-crypt".dependencies.requires;
  initrdOwnsCrypt = service.enable && service.activationOwner == "image" && !service.autoStart;
  hostDoesNotUnlock = !host.aos.services."measured-var.aos-var-crypt".enable;
  bootIdentityRequired = builtins.elem "aos-boot-identity-guard.service" service.dependencies.requires;
  controllerCompletesBeforeUnlock = builtins.elem "aos-ability-initrd-controller.service" service.dependencies.after;
  unlockPrecedesVar = builtins.elem "mount-var.service" service.dependencies.before;
  verityRequiredWhenRequested = builtins.elem "aos-verity-root-verify.service" service.dependencies.requires;
  verityOptionalOtherwise = !builtins.elem "aos-verity-root-verify.service" normal.aos.services."measured-var.aos-var-crypt".dependencies.requires;
  recoverySkipsEnrollment = builtins.any (condition: condition.kind == "kernel-argument" && condition.argument == "aos.recovery=1" && condition.negated) service.conditions.all;
  denialUnitRetainedForManualTest = denial.enable && !denial.autoStart;
  selinuxContextEnforced = denial.policy.hardening.security_label == "system_u:system_r:aos_selinux_native_service_t";
  denialCommandPreserved = (builtins.head denial.lifecycle.start).executable.arguments == ["/tmp/aos-selinux-denied"];
}
