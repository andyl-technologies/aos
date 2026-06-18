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
    '';
  }
