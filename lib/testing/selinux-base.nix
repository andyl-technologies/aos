##! lib/testing/selinux-base.nix — SELinux base policy VM smoke check.
{
  pkgs,
  mkSystem,
  testing,
}: let
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
        ];
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
      def assert_refpolicy_loaded():
          vm.wait_until_succeeds("systemctl is-active selinux-policy-load.service", timeout=360)
          vm.succeed("test -d /sys/fs/selinux")
          vm.succeed("test -f /sys/fs/selinux/enforce")
          vm.succeed("test \"$(cat /sys/fs/selinux/enforce)\" = 1")
          vm.succeed("test -f /etc/selinux/refpolicy/policy/policy.*")
          vm.succeed("test -x /usr/libexec/selinux/hll/pp")
          vm.succeed("semodule -s refpolicy -l | grep -E '^base\\b'")

      assert_refpolicy_loaded()

      vm.reboot()
      assert_refpolicy_loaded()

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
      cat > /tmp/aos_selinux_generated.te <<'EOF'
      module aos_selinux_generated 1.0;

      require {
        type init_t;
        type kernel_t;
        type unlabeled_t;
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

      type aos_selinux_generated_t;
      typeattribute aos_selinux_generated_t domain;
      role system_r types aos_selinux_generated_t;

      allow aos_selinux_generated_t init_t:fd use;
      allow init_t aos_selinux_generated_t:process dyntransition;
      allow init_t aos_selinux_generated_t:process2 { nnp_transition nosuid_transition };
      allow aos_selinux_generated_t kernel_t:fd use;
      allow kernel_t aos_selinux_generated_t:process dyntransition;
      allow kernel_t aos_selinux_generated_t:process2 { nnp_transition nosuid_transition };
      allow aos_selinux_generated_t self:process { execmem execstack execheap };
      allow aos_selinux_generated_t self:process2 { nnp_transition nosuid_transition };
      allow aos_selinux_generated_t file_type:file execmod;
      allow aos_selinux_generated_t unlabeled_t:dir { getattr open read search };
      allow aos_selinux_generated_t unlabeled_t:file { execute execute_no_trans execmod getattr map open read };
      allow aos_selinux_generated_t unlabeled_t:lnk_file { getattr read };
      EOF
      checkmodule -M -m -o /tmp/aos_selinux_generated.mod /tmp/aos_selinux_generated.te
      semodule_package -o /tmp/aos_selinux_generated.pp -m /tmp/aos_selinux_generated.mod
      semodule -s refpolicy -i /tmp/aos_selinux_generated.pp
      semodule -s refpolicy -l | grep -E '^aos_selinux_generated\\b'

      systemd-run --wait --collect \
        --unit=aos-selinux-generated-true \
        --property=Type=oneshot \
        --property=NoNewPrivileges=true \
        ${pkgs.aos-selinux-run}/bin/aos-selinux-run \
          --context system_u:system_r:aos_selinux_generated_t \
          -- ${pkgs.aos-landlock}/bin/aos-landlock --require-abi 4 --fs-ro / -- ${pkgs.coreutils}/bin/true || {
        systemctl status --no-pager aos-selinux-generated-true.service || true
        journalctl -b --no-pager -u aos-selinux-generated-true.service || true
        journalctl -k -b --no-pager | grep -Ei 'avc|selinux' || true
        exit 1
      }

      rm -f /tmp/aos-selinux-denied
      if systemd-run --wait --collect \
        --unit=aos-selinux-generated-deny \
        --property=Type=oneshot \
        --property=NoNewPrivileges=true \
        ${pkgs.aos-selinux-run}/bin/aos-selinux-run \
          --context system_u:system_r:aos_selinux_generated_t \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-selinux-denied
      then
        echo "generated SELinux domain unexpectedly wrote /tmp/aos-selinux-denied" >&2
        exit 1
      fi
      test ! -e /tmp/aos-selinux-denied
      """, timeout=120)
    '';
  }
