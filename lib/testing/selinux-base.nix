##! lib/testing/selinux-base.nix — SELinux base policy VM smoke check.
{
  pkgs,
  mkSystem,
  testing,
}: let
  generatedModule = "aos_x2eselinux_x2dgenerated";
  generatedType = "${generatedModule}_t";
  generatedPackage = pkgs.mkDerivation {
    pname = "selinux-generated-expose";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/selinux-generated-expose"
          printf selinux-generated-expose > "$out/share/selinux-generated-expose/payload.txt"
        '';
      }
    ];

    expose = {
      units."selinux-generated-expose.service" = {
        description = "RFC-0001 generated SELinux package domain service";
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.coreutils}/bin/sleep 300";
        };
      };
      units."selinux-generated-expose-deny.service" = {
        description = "RFC-0001 generated SELinux package domain denial service";
        onlyManualStart = true;
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.coreutils}/bin/touch /tmp/aos-selinux-denied";
        };
      };
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        kernel-modules = [];
        syscalls = "restricted";
        security-label = "aos.selinux-generated";
      };
    };
  };
  generatedExpose = generatedPackage.expose;
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
        ];

        aos.packages.selinux-generated-expose = {
          package = generatedPackage;
          bundle = true;
          preset = true;
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
      test -s ${generatedExpose}/mac/selinux/${generatedModule}.pp
      test -s ${generatedExpose}/mac/selinux/${generatedModule}.mod
      test -f ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'module ${generatedModule} 1.0;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'typeattribute ${generatedType} domain;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'class fd use;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} init_t:fd use;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} kernel_t:fd use;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} file_type:file execmod;' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} root_t:dir { getattr open read search };' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} tmp_t:dir { getattr open read search };' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} tmpfs_t:dir { getattr open read search };' ${generatedExpose}/mac/selinux/${generatedModule}.te
      grep -Fq 'allow ${generatedType} var_lib_t:dir { getattr open read search };' ${generatedExpose}/mac/selinux/${generatedModule}.te
      """, timeout=120)

      vm.succeed("""
      set -eu
      target=aos-pkg-selinux-generated-expose.target
      mac=aos-pkg-selinux-generated-expose-mac.service
      unit=selinux-generated-expose.service
      deny=selinux-generated-expose-deny.service

      AOS_EXPOSE_START_NO_WAIT=1 ${pkgs.aos.packageRuntime}/bin/aos-package-runtime _test-reconcile-exposed-units --system
      test -L /etc/systemd/system.attached/$target
      test -L /etc/systemd/system.attached/$mac
      test -L /etc/systemd/system.attached/$unit
      test -L /etc/systemd/system.attached/$deny
      grep -E '^Wants=.*aos-pkg-selinux-generated-expose-mac\\.service' /etc/systemd/system.attached/$target
      grep -E '^Wants=.*selinux-generated-expose\\.service' /etc/systemd/system.attached/$target
      if grep -E '^Wants=.*selinux-generated-expose-deny\\.service' /etc/systemd/system.attached/$target; then
        echo "manual denial service must not be wanted by $target" >&2
        exit 1
      fi
      systemctl cat $mac | grep -F '# /etc/systemd/system.attached/'"$mac"
      systemctl cat $unit | grep -F '# /etc/systemd/system.attached/'"$unit"
      systemctl cat $deny | grep -F '# /etc/systemd/system.attached/'"$deny"
      systemctl cat $unit | grep -E '^Requires=.*aos-pkg-selinux-generated-expose-mac\\.service'
      systemctl cat $unit | grep -E '^After=.*aos-pkg-selinux-generated-expose-mac\\.service'
      systemctl cat $deny | grep -E '^Requires=.*aos-pkg-selinux-generated-expose-mac\\.service'
      systemctl cat $deny | grep -E '^After=.*aos-pkg-selinux-generated-expose-mac\\.service'
      systemctl cat $deny | grep -F 'X-OnlyManualStart=true'

      exec_start=$(grep '^ExecStart=' /etc/systemd/system.attached/$unit)
      exec_start=''${exec_start#ExecStart=}
      deny_start=$(grep '^ExecStart=' /etc/systemd/system.attached/$deny)
      deny_start=''${deny_start#ExecStart=}
      case "$exec_start" in
        *'aos-selinux-run --context system_u:system_r:${generatedType} -- '*'aos-landlock '*)
          ;;
        *)
          echo "generated workload ExecStart does not enter ${generatedType} before Landlock: $exec_start" >&2
          exit 1
          ;;
      esac
      case "$deny_start" in
        *'aos-selinux-run --context system_u:system_r:${generatedType} -- '*'aos-landlock '*)
          ;;
        *)
          echo "generated denial ExecStart does not enter ${generatedType} before Landlock: $deny_start" >&2
          exit 1
          ;;
      esac

      systemctl reset-failed $target $mac $unit $deny || true
      systemctl start $target || {
        systemctl status --no-pager $target $mac $unit $deny || true
        journalctl -b --no-pager -u $target -u $mac -u $unit -u $deny || true
        journalctl -k -b --no-pager | grep -Ei 'avc|selinux' || true
        exit 1
      }
      loaded=0
      attempts=0
      while [ "$attempts" -lt 60 ]; do
        if semodule -s refpolicy -l | grep -E '^${generatedModule}\\b'; then
          loaded=1
          break
        fi
        attempts=$((attempts + 1))
        sleep 1
      done
      if [ "$loaded" != 1 ]; then
        systemctl status --no-pager $target $mac $unit $deny || true
        journalctl -b --no-pager -u $target -u $mac -u $unit -u $deny || true
        journalctl -k -b --no-pager | grep -Ei 'avc|selinux' || true
        systemctl cat $target $mac $unit $deny || true
        ls -l /etc/systemd/system.attached || true
        exit 1
      fi

      systemctl start $unit || {
        systemctl status --no-pager $unit || true
        journalctl -b --no-pager -u $unit || true
        journalctl -k -b --no-pager | grep -Ei 'avc|selinux' || true
        exit 1
      }
      pid=$(systemctl show --property=MainPID --value $unit)
      if [ -z "$pid" ] || [ "$pid" = 0 ]; then
        systemctl status --no-pager $unit || true
        echo "generated SELinux service did not report a running MainPID" >&2
        exit 1
      fi
      context=$(cat "/proc/$pid/attr/current")
      case "$context" in
        system_u:system_r:${generatedType}|system_u:system_r:${generatedType}:s0)
          ;;
        *)
          systemctl status --no-pager $unit || true
          echo "generated SELinux service ran with unexpected context: $context" >&2
          exit 1
          ;;
      esac
      systemctl stop $unit

      rm -f /tmp/aos-selinux-denied
      if systemctl start $deny; then
        echo "generated SELinux domain unexpectedly wrote /tmp/aos-selinux-denied" >&2
        exit 1
      fi
      test ! -e /tmp/aos-selinux-denied
      """, timeout=120)
    '';
  }
