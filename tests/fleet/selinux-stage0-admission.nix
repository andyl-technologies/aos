# Immutable SELinux stage-0 admission and fail-closed policy tests.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  admissionTarget = "aos-selinux-admission.target";
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  enrolledFirmwareVarsPath = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
  stage0Fixture = import ./_selinux-stage0-fixture.nix {inherit lib pkgs;};
  canonicalPolicy = "${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  invalidPolicy = pkgs.writeTextFile {
    name = "invalid-selinux-policy";
    destination = "/policy.33";
    text = "not a binary SELinux policy\n";
  };
  mismatchedPolicy = pkgs.runCommand "mismatched-selinux-policy.33" {} ''
    set -eu
    rmdir "$out"

    # Preserve the canonical length while replacing its nonzero magic byte.
    printf '\000' > "$out"
    ${pkgs.coreutils}/bin/tail -c +2 ${canonicalPolicy} >> "$out"
    test "$(${pkgs.coreutils}/bin/stat -c %s "$out")" \
      -eq "$(${pkgs.coreutils}/bin/stat -c %s ${canonicalPolicy})"
    ! ${pkgs.diffutils}/bin/cmp "$out" ${canonicalPolicy}
  '';

  runtimeValidStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = admissionTarget;
  };
  runtimeInvalidStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = admissionTarget;
    loadedPolicy = "${invalidPolicy}/policy.33";
  };
  runtimeMismatchStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = admissionTarget;
    expectedPolicy = mismatchedPolicy;
  };

  canonicalStage0 = pkgs.aos-selinux-stage0;
  loadedPolicyOverride = pkgs.aosSelinuxStage0With {
    loadedPolicy = "${invalidPolicy}/policy.33";
  };
  expectedPolicyOverride = pkgs.aosSelinuxStage0With {
    expectedPolicy = mismatchedPolicy;
  };
  admissionOverride = pkgs.aosSelinuxStage0With {
    admissionUnit = admissionTarget;
  };
  immutablePolicyOverride = canonicalStage0 // {
    immutablePolicy = invalidPolicy;
  };
  runtimeRootsOverride = canonicalStage0 // {
    runtimeRootsProvisioner = invalidPolicy;
  };
  postPinGateOverride = canonicalStage0 // {
    qualificationPostPinGate = "/run/aos/not-production";
  };

  admissionModule = stage0:
    lib.mkMerge [
      (stage0Fixture stage0)
      {
        boot.initrd.systemd.targets."aos-selinux-admission" = {
          description = "AOS SELinux immutable admission";
          unitConfig = {
            DefaultDependencies = "no";
            Conflicts = "initrd-root-fs.target initrd-switch-root.target";
          };
        };

        boot.initrd.systemd.services."aos-selinux-admission-proof" = {
          description = "Prove enforcing init_t admission without real-root access";
          requiredBy = [admissionTarget];
          unitConfig.DefaultDependencies = "no";
          serviceConfig = {
            Type = "oneshot";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
          script = ''
            set -eu

            pid_one_context="$(${pkgs.coreutils}/bin/cat /proc/1/attr/current)"
            self_context="$(${pkgs.coreutils}/bin/cat /proc/self/attr/current)"
            secure_boot="$(${pkgs.coreutils}/bin/od -An -tu1 -j4 -N1 \
              /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c \
              | ${pkgs.coreutils}/bin/tr -d ' ')"
            setup_mode="$(${pkgs.coreutils}/bin/od -An -tu1 -j4 -N1 \
              /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c \
              | ${pkgs.coreutils}/bin/tr -d ' ')"
            test "$pid_one_context" = "system_u:system_r:init_t"
            test "$secure_boot" -eq 1
            test "$setup_mode" -eq 0
            test ! -e /dev/mapper/root
            ! ${pkgs.util-linux}/bin/mountpoint -q /sysroot
            ! ${pkgs.util-linux}/bin/mountpoint -q /sysroot/var

            echo "AOS SELinux admission proof: pid1=$pid_one_context self=$self_context secureboot=$secure_boot setupmode=$setup_mode"
          '';
        };

        # This gate terminates in the admission-only initrd target, so keep the
        # unrelated system-root image cheap when the fleet harness materializes it.
        aos.image.erofsCompressionLevel = 1;
      }
    ];

  productionModule = {
    aos.security.selinux = {
      enable = true;
      bootMode = "immutable-stage0";
    };
  };
  productionSystemFor = stage0:
    systems.server-secureboot-lockdown.extendModules {
      modules = [
        productionModule
        (lib.mkIf (stage0 != null) {
          aos.boot.initrd.stage0 = lib.mkForce stage0;
        })
      ];
    };
  failedAssertionMessages = evaluated:
    builtins.map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) evaluated.config.assertions
    );
  rejects = message: evaluated:
    builtins.elem message (failedAssertionMessages evaluated);

  productionSystem = productionSystemFor null;
  loadedOverrideSystem = productionSystemFor loadedPolicyOverride;
  expectedOverrideSystem = productionSystemFor expectedPolicyOverride;
  immutableOverrideSystem = productionSystemFor immutablePolicyOverride;
  admissionOverrideSystem = productionSystemFor admissionOverride;
  runtimeRootsOverrideSystem = productionSystemFor runtimeRootsOverride;
  postPinGateOverrideSystem = productionSystemFor postPinGateOverride;

  systemFor = stage0:
    systems.server-secureboot-lockdown.extendModules {
      modules = [(admissionModule stage0)];
    };
  validSystem = systemFor runtimeValidStage0;
  invalidSystem = systemFor runtimeInvalidStage0;
  mismatchSystem = systemFor runtimeMismatchStage0;
  validConfig = validSystem.config;
in
  assert productionSystem.config.aos.boot.initrd.stage0 == canonicalStage0;
  assert productionSystem.config.aos.boot.initrd.stage0.loadedPolicy == canonicalPolicy;
  assert productionSystem.config.aos.boot.initrd.stage0.expectedPolicy == canonicalPolicy;
  assert productionSystem.config.aos.boot.initrd.stage0.immutablePolicy == pkgs.aos-selinux-production-policy;
  assert productionSystem.config.aos.boot.initrd.stage0.runtimeRootsProvisioner == pkgs.aos-selinux-runtime-roots;
  assert productionSystem.config.aos.boot.initrd.stage0.admissionUnit == "aos-selinux-stage0-hold.target";
  assert rejects "immutable SELinux stage 0 must load the canonical production policy." loadedOverrideSystem;
  assert rejects "immutable SELinux stage 0 must authenticate the canonical production policy." expectedOverrideSystem;
  assert rejects "immutable SELinux stage 0 must identify the canonical immutable policy derivation." immutableOverrideSystem;
  assert rejects "immutable SELinux stage 0 must retain the production admission hold target." admissionOverrideSystem;
  assert rejects "immutable SELinux stage 0 must authenticate the canonical runtime-root provisioner." runtimeRootsOverrideSystem;
  assert rejects "immutable SELinux stage 0 forbids the qualification post-pin gate in production composition." postPinGateOverrideSystem;
  assert validConfig.aos.boot.initrd.stage0 == runtimeValidStage0;
  assert validConfig.system.build.immutableSelinuxPolicy == pkgs.aos-selinux-production-policy;
  assert !(builtins.hasAttr "selinux-policy-load" validConfig.systemd.services);
  assert !(builtins.hasAttr "selinux-autorelabel" validConfig.systemd.services);
  assert lib.count (parameter: parameter == "selinux=1") validConfig.aos.boot.kernelParams == 1;
  assert lib.count (parameter: parameter == "security=selinux") validConfig.aos.boot.kernelParams == 1;
  assert lib.count (parameter: parameter == "enforcing=1") validConfig.aos.boot.kernelParams == 1;
  assert lib.count (parameter: parameter == "aos.selinux.root_handoff=1") validConfig.aos.boot.kernelParams == 1;
  assert lib.count (parameter: parameter == "rootflags=nodev") validConfig.aos.boot.kernelParams == 1;
  assert lib.any (lib.hasInfix "CONFIG_SECURITY_SELINUX=y") validConfig.aos.kernel._extraConfigFragments;
  assert lib.any (lib.hasInfix "CONFIG_SECURITY_LOCKDOWN_LSM=y") validConfig.aos.kernel._extraConfigFragments; {
    name = "selinux-stage0-admission";
    timeout = 1800;
    bootTimeout = 180;

    machines = {
      valid = {
        system = validSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
        expectAgent = false;
      };
      invalid = {
        system = invalidSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
        expectAgent = false;
      };
      mismatch = {
        system = mismatchSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
        expectAgent = false;
      };
    };

    testScript =
      # python
      ''
        import time
        from pathlib import Path

        def await_serial(machine, marker):
            serial_log = Path(machine.serial_log_path)
            deadline = time.monotonic() + 120
            transcript = ""
            stable_since = None

            while time.monotonic() < deadline:
                if serial_log.exists():
                    observed = serial_log.read_text(errors="replace")
                    if marker in observed:
                        if observed != transcript:
                            transcript = observed
                            stable_since = time.monotonic()
                        elif stable_since is not None and time.monotonic() - stable_since >= 3:
                            return transcript
                time.sleep(1)

            raise AssertionError(
                f"timed out waiting for {marker!r}:\n{transcript[-12000:]}"
            )

        valid_log = await_serial(valid, "Reached target AOS SELinux immutable admission")
        assert "policy exact and enforcing; entering init_t guard" in valid_log
        assert "PID 1 is init_t; handing off to physically labeled systemd" in valid_log
        assert "AOS SELinux admission proof: pid1=system_u:system_r:init_t" in valid_log
        assert "secureboot=1 setupmode=0" in valid_log
        assert "Reached target AOS SELinux immutable admission" in valid_log
        assert "Switching root" not in valid_log
        assert "aos-verity-root-verify" not in valid_log
        assert "Mount /var Partition" not in valid_log

        invalid_log = await_serial(invalid, "kernel rejected SELinux policy:")
        assert "policy exact and enforcing" not in invalid_log
        assert "handing off to physically labeled systemd" not in invalid_log
        assert "Switching root" not in invalid_log

        mismatch_log = await_serial(
            mismatch,
            "kernel SELinux policy differs from the trusted expectation",
        )
        assert "policy exact and enforcing" not in mismatch_log
        assert "handing off to physically labeled systemd" not in mismatch_log
        assert "Switching root" not in mismatch_log
      '';
  }
