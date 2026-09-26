##! lib/testing/selinux-base.nix — SELinux base policy VM smoke check.
{
  pkgs,
  lib,
  mkSystem,
  testing,
}: let
  generatedModule = "aos_selinux_native_service";
  generatedType = "${generatedModule}_t";
  packageModuleRoot = builtins.path {
    path = ../../tests/fixtures/selinux-base-package;
    name = "aos-selinux-base-test-package-module";
  };
  generatedPolicySource = pkgs.writeTextFile {
    name = "${generatedModule}.te";
    destination = "/${generatedModule}.te";
    text = ''
      module ${generatedModule} 1.0;

      require {
        type init_t;
        type kernel_t;
        type root_t;
        type tmp_t;
        type tmpfs_t;
        type unlabeled_t;
        type var_lib_t;
        type var_t;
        attribute domain;
        attribute file_type;
        role system_r;
        class dir { getattr open read search };
        class fd use;
        class file { execute execute_no_trans execmod getattr map open read };
        class lnk_file { getattr read };
        class process { dyntransition execmem execstack execheap };
        class process2 { nnp_transition nosuid_transition };
      }

      type ${generatedType};
      typeattribute ${generatedType} domain;
      role system_r types ${generatedType};

      allow ${generatedType} init_t:fd use;
      allow init_t ${generatedType}:process dyntransition;
      allow init_t ${generatedType}:process2 { nnp_transition nosuid_transition };
      allow ${generatedType} kernel_t:fd use;
      allow kernel_t ${generatedType}:process dyntransition;
      allow kernel_t ${generatedType}:process2 { nnp_transition nosuid_transition };
      allow ${generatedType} self:process { execmem execstack execheap };
      allow ${generatedType} self:process2 { nnp_transition nosuid_transition };
      allow ${generatedType} file_type:file execmod;
      allow ${generatedType} root_t:dir { getattr open read search };
      allow ${generatedType} tmp_t:dir { getattr open read search };
      allow ${generatedType} tmp_t:lnk_file { getattr read };
      allow ${generatedType} tmpfs_t:dir { getattr open read search };
      allow ${generatedType} tmpfs_t:lnk_file { getattr read };
      allow ${generatedType} unlabeled_t:dir { getattr open read search };
      allow ${generatedType} unlabeled_t:file { execute execute_no_trans execmod getattr map open read };
      allow ${generatedType} unlabeled_t:lnk_file { getattr read };
      allow ${generatedType} var_t:dir { getattr open read search };
      allow ${generatedType} var_t:lnk_file { getattr read };
      allow ${generatedType} var_lib_t:dir { getattr open read search };
      allow ${generatedType} var_lib_t:lnk_file { getattr read };
    '';
  };
  generatedPolicy = pkgs.mkDerivation {
    pname = generatedModule;
    version = "1.0";
    src = null;
    buildDeps = [pkgs.checkpolicy pkgs.semodule-utils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${generatedPolicySource}/${generatedModule}.te "$out/${generatedModule}.te"
          checkmodule -M -m -o "$out/${generatedModule}.mod" "$out/${generatedModule}.te"
          semodule_package -o "$out/${generatedModule}.pp" -m "$out/${generatedModule}.mod"
        '';
      }
    ];
  };
  system = mkSystem {
    modules = [
      {
        aos.system.name = "aos-selinux-base-test";
        aos.security.selinux = {
          enable = true;
          mode = "enforcing";
          policy = "refpolicy";
          autorelabel = false;
        };

        environment.systemPackages = [
          pkgs.aos-landlock
          pkgs.aos-selinux-run
          pkgs.checkpolicy
          pkgs.semodule-utils
          # `semodule` (the policy loader) lives in policycoreutils; image
          # slimming dropped it from the server PATH (semodule-utils only
          # provides semodule_package/_link/_expand).
          pkgs.policycoreutils
          pkgs.coreutils
        ];
      }
    ];
    packageModules = [
      {
        name = "selinux-base-test";
        version = "1";
        configRoot = builtins.toString packageModuleRoot;
        module = "${packageModuleRoot}/module.nix";
        outputs = {
          self = builtins.toString packageModuleRoot;
          dependencies.coreutils = builtins.toString pkgs.coreutils;
        };
      }
    ];
  };
in
  testing.mkVMTest {
    name = "selinux-base";
    inherit system;
    seedSELinuxDisabledConfig = false;
    timeout = 420;
    memory = 3072;
    testScript = ''
      import textwrap

      def assert_refpolicy_loaded():
          vm.wait_until_succeeds(
              "test -d /sys/fs/selinux "
              "&& test -f /sys/fs/selinux/enforce "
              "&& test \"$(cat /sys/fs/selinux/enforce)\" = 1 "
              "&& test -f /etc/selinux/refpolicy/policy/policy.* "
              "&& test -x /usr/libexec/selinux/hll/pp "
              "&& semodule -s refpolicy -l | grep -E '^base\\b'",
              timeout=360,
          )

      def allow_test_agent_systemd_control():
          vm.succeed(textwrap.dedent("""\
          cat > /tmp/aos_selinux_test_agent_systemd.te <<'EOF'
          module aos_selinux_test_agent_systemd 1.0;

          require {
            type kernel_t;
            type unlabeled_t;
            class service { reload start status stop };
          }

          allow kernel_t unlabeled_t:service { reload start status stop };
          EOF
          checkmodule -M -m -o /tmp/aos_selinux_test_agent_systemd.mod /tmp/aos_selinux_test_agent_systemd.te
          semodule_package -o /tmp/aos_selinux_test_agent_systemd.pp -m /tmp/aos_selinux_test_agent_systemd.mod
          semodule -s refpolicy -i /tmp/aos_selinux_test_agent_systemd.pp
          semodule -s refpolicy -l | grep -E '^aos_selinux_test_agent_systemd\\b'
          """), timeout=120)

      assert_refpolicy_loaded()
      allow_test_agent_systemd_control()

      vm.reboot()
      assert_refpolicy_loaded()
      allow_test_agent_systemd_control()

      vm.succeed("""
      cat > /tmp/aos_selinux_smoke.te <<'EOF'
      module aos_selinux_smoke 1.0;

      require {
        role system_r;
      }

      type aos_selinux_smoke_t;
      role system_r types aos_selinux_smoke_t;
      EOF
      checkmodule -M -m -o /tmp/aos_selinux_smoke.mod /tmp/aos_selinux_smoke.te
      semodule_package -o /tmp/aos_selinux_smoke.pp -m /tmp/aos_selinux_smoke.mod
      semodule -s refpolicy -i /tmp/aos_selinux_smoke.pp
      semodule -s refpolicy -l | grep -E '^aos_selinux_smoke\\b'
      """, timeout=120)

      vm.succeed("""
      set -eu
      unit=selinux-native.service
      deny=selinux-native-deny.service

      test -f ${generatedPolicy}/${generatedModule}.te
      test -s ${generatedPolicy}/${generatedModule}.mod
      test -s ${generatedPolicy}/${generatedModule}.pp
      semodule -s refpolicy -i ${generatedPolicy}/${generatedModule}.pp
      semodule -s refpolicy -l | grep -E '^${generatedModule}\\b'

      systemctl cat $unit | grep -F 'SELinuxContext=system_u:system_r:${generatedType}'
      systemctl cat $deny | grep -F 'SELinuxContext=system_u:system_r:${generatedType}'
      systemctl cat $unit | grep -F '${pkgs.coreutils}/bin/sleep 300'
      systemctl cat $deny | grep -F '${pkgs.coreutils}/bin/touch /tmp/aos-selinux-denied'

      systemctl reset-failed $unit $deny || true
      systemctl restart $unit || {
        systemctl status --no-pager $unit || true
        journalctl -b --no-pager -u $unit || true
        journalctl -k -b --no-pager | grep -Ei 'avc|selinux' || true
        exit 1
      }
      pid=$(systemctl show --property=MainPID --value $unit)
      if [ -z "$pid" ] || [ "$pid" = 0 ]; then
        systemctl status --no-pager $unit || true
        echo "native SELinux service did not report a running MainPID" >&2
        exit 1
      fi
      context=$(cat "/proc/$pid/attr/current")
      case "$context" in
        system_u:system_r:${generatedType}|system_u:system_r:${generatedType}:s0)
          ;;
        *)
          systemctl status --no-pager $unit || true
          echo "native SELinux service ran with unexpected context: $context" >&2
          exit 1
          ;;
      esac
      systemctl stop $unit

      rm -f /tmp/aos-selinux-denied
      if systemctl start $deny; then
        echo "native SELinux service unexpectedly wrote /tmp/aos-selinux-denied" >&2
        exit 1
      fi
      test ! -e /tmp/aos-selinux-denied
      """, timeout=120)
    '';
  }
