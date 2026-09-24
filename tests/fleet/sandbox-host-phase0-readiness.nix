# Live qualification of the signed, non-authorizing Host phase-0 surrogate.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  hostPackage = pkgs.aos-sandbox-hostd;
  inspector = "${hostPackage}/bin/aos-sandbox-host-phase0-probe";
  hostd = "${hostPackage}/bin/aos-sandbox-hostd";
  nspawn = "${pkgs.systemd}/bin/systemd-nspawn";
  policy = "${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  report = "/var/lib/aos/sandbox-host-phase0/probe-v2";

  # RFC 8032's first Ed25519 vector is public test data, never a deployable key.
  testKeys = pkgs.runCommand "aos-host-phase0-rfc8032-test-keys" {} ''
    mkdir -p "$out"
    printf '%s' 'nWGxne/9WmC6hCr0kuwsxERJxWl7MmkZcDusAxyuf2A=' \
      | ${pkgs.coreutils}/bin/base64 -d > "$out/seed"
    printf '%s' '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' \
      | ${pkgs.coreutils}/bin/base64 -d > "$out/public"
    test "$(${pkgs.coreutils}/bin/stat -c %s "$out/seed")" -eq 32
    test "$(${pkgs.coreutils}/bin/stat -c %s "$out/public")" -eq 32
  '';
  testPublicPem = pkgs.writeTextFile {
    name = "aos-host-phase0-rfc8032-test-public.pem";
    text = ''
      -----BEGIN PUBLIC KEY-----
      MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
      -----END PUBLIC KEY-----
    '';
  };

  system = systems.server-secureboot-lockdown.extendModules {
    modules = [
      ({config, ...}: {
        aos.security.selinux = {
          enable = true;
          bootMode = "immutable-stage0";
          _qualificationAdmissionRelease = true;
        };
        aos.boot.initrd.stage0 = lib.mkForce (pkgs.aosSelinuxStage0With {
          admissionUnit = "";
          expectedPolicy = "${pkgs.aosSelinuxKernelPolicyReadbackForKernel config.system.build.kernel}/policy.33";
          expectedPolicyKernel = config.system.build.kernel;
        });
        aos.services.dbus.enable = true;
        aos.sandbox.hostBroker = {
          enable = true;
          credentials = {
            brokerPlanPolicy = "phase0-unused-plan-policy";
            brokerPlanPublicKey = "phase0-unused-plan-key";
            brokerRevocationScope = "phase0-unused-revocation";
            ownershipLeasePolicy = "phase0-unused-lease-policy";
            ownershipLeasePublicKey = "phase0-unused-lease-key";
            nodeId = "phase0-unused-node-id";
            journalMacKey = "phase0-unused-journal-key";
            phase0ProbeSigningSeed = "phase0-test-seed";
            phase0ProbePublicKey = "phase0-test-public";
          };
        };

        # The broker itself is not started: no BackendReadiness producer exists.
        # Only the fixed target/inspector units are started by this gate.
        environment.etc."tmpfiles.d/aos-host-phase0-test-credentials.conf".text = ''
          d /run/credentials/@system 0700 root root - -
          C /run/credentials/@system/phase0-test-seed 0600 root root - ${testKeys}/seed
          C /run/credentials/@system/phase0-test-public 0600 root root - ${testKeys}/public
        '';
        environment.systemPackages = [pkgs.coreutils pkgs.openssl pkgs.systemd];
        aos.image.erofsCompressionLevel = 1;
        aos.image.budgets = {
          maxRootMiB = 768;
          maxDownloadMiB = 832;
          maxConvertedDownloadMiB = 928;
        };
      })
    ];
  };
in {
  name = "sandbox-host-phase0-readiness";
  timeout = 1800;
  bootTimeout = 300;

  machines.vm = {
    inherit system;
    bootMode = "image";
    firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
  };

  testScript =
    # python
    ''
      import base64
      import struct

      TARGET = "aos-sandbox-host-phase0-target.service"
      INSPECTOR = "aos-sandbox-host-phase0-inspector.service"
      REPORT = "${report}"
      OVERRIDE = f"/run/systemd/system/{TARGET}.d/qualification.conf"

      def start_inspector(expect_success, rejection=None):
          vm.succeed(f"systemctl stop {INSPECTOR} {TARGET} || true")
          vm.succeed(f"rm -f {REPORT}")
          vm.succeed(f"systemctl reset-failed {INSPECTOR} {TARGET}")
          status, output, error = vm.execute(f"systemctl start {INSPECTOR}", timeout=35)
          if expect_success:
              assert status == 0, (status, output, error, vm.succeed(
                  f"journalctl -u {TARGET} -u {INSPECTOR} --no-pager -n 80"))
              vm.succeed(f"test -s {REPORT}")
          else:
              assert status != 0, (status, output, error)
              vm.fail(f"test -e {REPORT}")
              journal = vm.succeed(f"journalctl -u {INSPECTOR} --no-pager -n 30")
              assert rejection in journal, journal

      def override_target(contents):
          vm.succeed(f"mkdir -p /run/systemd/system/{TARGET}.d")
          vm.succeed(f"printf '%b\\n' '{contents}' > {OVERRIDE}")
          vm.succeed("systemctl daemon-reload")

      vm.wait_for_unit("multi-user.target", timeout=180)
      vm.succeed("test -f /sys/fs/selinux/enforce")
      assert vm.succeed("cat /sys/fs/selinux/enforce").strip() == "1"
      vm.succeed("test -s /run/credentials/@system/phase0-test-seed")
      vm.succeed("test -s /run/credentials/@system/phase0-test-public")
      vm.fail("systemctl is-active --quiet aos-sandbox-hostd.service")

      start_inspector(True)
      encoded = vm.succeed(f"base64 -w0 {REPORT}").strip()
      signed = base64.b64decode(encoded)
      assert len(signed) == 304 and signed[:8] == b"AOSHPB02", signed[:8]

      # Verify the deployed report's actual Ed25519 signature, not merely its
      # presence. The public key is the independently loaded test pin.
      vm.succeed(f"head -c 240 {REPORT} > /run/phase0-message")
      vm.succeed(f"tail -c 64 {REPORT} > /run/phase0-signature")
      vm.succeed(
          "${pkgs.openssl}/bin/openssl pkeyutl -verify -pubin "
          "-inkey ${testPublicPem} -rawin -in /run/phase0-message "
          "-sigfile /run/phase0-signature"
      )
      assert signed[8:24] == bytes.fromhex(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip().replace("-", ""))
      for offset, path in (
          (24, "${nspawn}"),
          (56, "${hostd}"),
          (88, "${inspector}"),
          (120, "${policy}"),
      ):
          digest = vm.succeed(f"sha256sum {path}").split()[0]
          assert signed[offset:offset + 32] == bytes.fromhex(digest), (offset, digest)

      target_pid = struct.unpack_from(">I", signed, 152)[0]
      assert target_pid > 1
      assert target_pid == int(vm.succeed(f"systemctl show {TARGET} -p MainPID --value"))
      assert vm.succeed(f"readlink /proc/{target_pid}/exe").strip() == "${inspector}"
      uid_map = vm.succeed(f"cat /proc/{target_pid}/uid_map").split()
      gid_map = vm.succeed(f"cat /proc/{target_pid}/gid_map").split()
      assert uid_map[0] == gid_map[0] == "0", (uid_map, gid_map)
      assert int(uid_map[1]) > 0 and int(gid_map[1]) > 0, (uid_map, gid_map)
      assert int(uid_map[2]) >= 65536 and int(gid_map[2]) >= 65536
      for property, expected in (
          ("NoNewPrivileges", "yes"),
          ("PrivateNetwork", "yes"),
          ("PrivateDevices", "yes"),
          ("ProtectSystem", "strict"),
      ):
          observed = vm.succeed(f"systemctl show {TARGET} -p {property} --value").strip()
          assert observed == expected, (property, observed)

      override_target("[Service]\\nExecStart=\\nExecStart=${pkgs.coreutils}/bin/sleep 60")
      start_inspector(False, "shifted target does not run the packaged inspector executable")

      override_target("[Service]\\nCapabilityBoundingSet=CAP_CHOWN")
      start_inspector(False, "shifted target capability or namespace policy is not closed")

      override_target("[Service]\\nRestrictNamespaces=no")
      start_inspector(False, "shifted target capability or namespace policy is not closed")

      vm.succeed(f"rm {OVERRIDE}")
      vm.succeed("systemctl daemon-reload")
      start_inspector(True)
      vm.fail("systemctl is-active --quiet aos-sandbox-hostd.service")
    '';
}
