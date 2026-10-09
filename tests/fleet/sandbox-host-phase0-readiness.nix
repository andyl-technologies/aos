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
  hostSyscallProfile = builtins.fromJSON (builtins.readFile ../../crates/aos-sandbox-host/src/plan/host_syscall_profile_v1.json);
  widenedHostFilter = lib.concatStringsSep " " (hostSyscallProfile.filter ++ ["ptrace"]);
  inspector = "${hostPackage}/bin/aos-sandbox-host-phase0-probe";
  hostd = "${hostPackage}/bin/aos-sandbox-hostd";
  credentialFixture = import ./_broker-session-credential-fixture.nix {inherit lib pkgs;};
  nspawn = "${pkgs.systemd}/bin/systemd-nspawn";
  policy = "${system.config.aos.security.selinux._canonicalReadback}/policy.33";
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
        # The fixture releases only admission. Its policy, kernel readback and
        # provisioner retain the image's exact UID and fixed-view assignments.
        aos.boot.initrd.stage0 = lib.mkForce (pkgs.aosSelinuxStage0With {
          aos-selinux-production-policy = config.aos.security.selinux._productionPolicy;
          aos-selinux-runtime-roots = config.aos.security.selinux._runtimeRootsProvisioner;
          admissionUnit = "";
          expectedPolicy = "${config.aos.security.selinux._canonicalReadback}/policy.33";
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
            brokerSessionManifest = "phase0-unused-host-session-manifest";
            brokerSessionHelloKey = "phase0-unused-host-session-hello";
            brokerSessionOutcomeKey = "phase0-unused-host-session-outcome";
            phase0ProbeSigningSeed = "phase0-test-seed";
            phase0ProbePublicKey = "phase0-test-public";
          };
        };

        # The broker starts in observation-only mode, with no BackendReadiness
        # credential and no nspawn launch configuration.
        environment.etc."tmpfiles.d/aos-host-phase0-test-credentials.conf".text = ''
          d /run/credentials/@system 0700 root root - -
          C /run/credentials/@system/phase0-test-seed 0600 root root - ${testKeys}/seed
          C /run/credentials/@system/phase0-test-public 0600 root root - ${testKeys}/public
        '';
        environment.systemPackages = [credentialFixture pkgs.coreutils pkgs.openssl pkgs.systemd];
        aos.image.erofsCompressionLevel = 1;
        # The nested Guest template copies fixed store bytes under independent
        # names and inodes. Reuse only their compressed data, never their labels.
        aos.image.erofsDeduplication = true;
        aos.image.budgets = {
          # This fixture carries a test-only credential harness alongside the
          # full sandbox closure; production runtime limits are unchanged.
          maxRuntimeClosureMiB = 1152;
          # The measured 844.9 MiB EROFS root carries the fixed Host services,
          # credential fixture, and full guest template in one image.
          maxRootMiB = 896;
          # The labeled stage-1 initrd is 207.1 MiB; its signed normal UKIs
          # are 223.5 MiB. These fixture bounds retain that complete payload.
          maxInitrdMiB = 224;
          maxUkiMiB = 256;
          # Peak publication retains two normal and three recovery UKIs.
          # Two 256 MiB normal images + three 64 MiB recovery images + 32 MiB
          # of FAT headroom preserve the existing transaction-size formula.
          maxEspMiB = 736;
          maxDownloadMiB = 960;
          # Bound the converted fixture by root + 736 MiB ESP + 16 MiB hash
          # partition + 16 MiB conversion/GPT overhead; root slots stay 1 GiB.
          maxConvertedDownloadMiB = 1664;
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
      import time

      TARGET = "aos-sandbox-host-phase0-target.service"
      INSPECTOR = "aos-sandbox-host-phase0-inspector.service"
      HOST = "aos-sandbox-hostd.service"
      REPORT = "${report}"
      OVERRIDE = f"/run/systemd/system/{TARGET}.d/qualification.conf"
      HOST_OVERRIDE = f"/run/systemd/system/{HOST}.d/qualification.conf"
      STALE_REPORT = "/run/phase0-stale-report"
      EXPECTED_HOST_SYSCALLS = set(${builtins.toJSON hostSyscallProfile.syscallsX86_64})

      def install_host_credentials():
          root = "/run/host-phase0-qualification"
          selected = vm.succeed(
              "${credentialFixture}/bin/broker-session-credential-fixture "
              "--ignored --list "
              "handshake::qualification_credentials::"
              "provision_controller_broker_credentials_after_boot"
          )
          assert "provision_controller_broker_credentials_after_boot: test" in selected
          output = vm.succeed(
              f"AOS_BSA_QUALIFICATION_ROOT={root} "
              "${credentialFixture}/bin/broker-session-credential-fixture "
              "--ignored --exact "
              "handshake::qualification_credentials::"
              "provision_controller_broker_credentials_after_boot "
              "--test-threads=1 --nocapture"
          )
          assert "CONTROLLER_BROKER_CREDENTIALS_STAGED" in output, output

          source = f"{root}/host-authority"
          session = f"{root}/sessions/host/broker"
          vm.succeed("install -d -m 0700 /run/credentials/@system")
          for installed, original in (
              ("phase0-unused-plan-policy", f"{source}/broker-plan-policy.cbor"),
              ("phase0-unused-plan-key", f"{source}/broker-plan-public-key"),
              ("phase0-unused-revocation", f"{source}/broker-revocation-scope"),
              ("phase0-unused-lease-policy", f"{source}/ownership-lease-policy.cbor"),
              ("phase0-unused-lease-key", f"{source}/ownership-lease-public-key"),
              ("phase0-unused-node-id", f"{source}/node-id"),
              ("phase0-unused-journal-key", f"{source}/journal-mac-key"),
              ("phase0-unused-host-session-manifest", f"{session}/broker-session-manifest"),
              ("phase0-unused-host-session-hello", f"{session}/broker-hello-signing-key"),
              ("phase0-unused-host-session-outcome", f"{session}/broker-outcome-signing-key"),
          ):
              vm.succeed(f"install -m 0400 {original} /run/credentials/@system/{installed}")

      def start_host(expect_success, rejection=None):
          vm.succeed(f"systemctl reset-failed {HOST}")
          status, output, error = vm.execute(f"systemctl start {HOST}", timeout=45)
          if expect_success:
              assert status == 0, (status, output, error, vm.succeed(
                  f"journalctl -u {HOST} --no-pager -n 80"))
              vm.wait_for_unit(HOST)
              time.sleep(2)
              vm.succeed(f"systemctl is-active --quiet {HOST}")
              pid = int(vm.succeed(f"systemctl show {HOST} -p MainPID --value"))
              assert pid > 1
              status_text = vm.succeed(f"cat /proc/{pid}/status")
              assert "CapEff:\t0000000000000000" in status_text
              assert "NoNewPrivs:\t1" in status_text
              assert "Seccomp:\t2" in status_text
              assert "Seccomp_filters:\t" in status_text
              filter_text = vm.succeed(f"systemctl show {HOST} -p SystemCallFilter --value")
              actual_syscalls = set(filter_text.split())
              assert actual_syscalls == EXPECTED_HOST_SYSCALLS, (
                  sorted(EXPECTED_HOST_SYSCALLS - actual_syscalls),
                  sorted(actual_syscalls - EXPECTED_HOST_SYSCALLS),
              )
              assert vm.succeed(
                  f"systemctl show {HOST} -p SystemCallErrorNumber --value"
              ).strip() == "1"
          else:
              vm.wait_until_fails(f"systemctl is-active --quiet {HOST}", timeout=15)
              journal = vm.succeed(f"journalctl -u {HOST} --no-pager -n 35")
              assert rejection in journal, (status, output, error, journal)

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

      # Data deduplication must not turn the nested Guest copy into a Host
      # inode alias, change immutable ownership/modes, or replace its label.
      outer_library = "${pkgs.openssl}/lib/libcrypto.so.4"
      guest_library = "${pkgs.aos-sandbox-guest-root-template}/root${pkgs.openssl}/lib/libcrypto.so.4"
      vm.succeed(f"cmp {outer_library} {guest_library}")
      identities = vm.succeed(f"stat -c '%d:%i' {outer_library} {guest_library}").splitlines()
      assert len(identities) == 2 and identities[0] != identities[1], identities
      metadata = vm.succeed(f"stat -c '%a %u %g' {outer_library} {guest_library}").splitlines()
      assert metadata == ["555 0 0", "555 0 0"], metadata
      contexts = vm.succeed(f"stat -c '%C' {outer_library} {guest_library}").splitlines()
      assert contexts == ["system_u:object_r:lib_t", "system_u:object_r:lib_t"], contexts

      vm.succeed("test -s /run/credentials/@system/phase0-test-seed")
      vm.succeed("test -s /run/credentials/@system/phase0-test-public")
      vm.fail("systemctl is-active --quiet aos-sandbox-hostd.service")
      install_host_credentials()

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

      start_host(True)
      first_report = vm.succeed(f"base64 -w0 {REPORT}").strip()
      vm.succeed(f"systemctl stop {TARGET}")
      vm.wait_until_fails(f"systemctl is-active --quiet {INSPECTOR}", timeout=15)
      vm.wait_until_fails(f"systemctl is-active --quiet {HOST}", timeout=15)
      start_host(True)
      renewed_report = vm.succeed(f"base64 -w0 {REPORT}").strip()
      assert renewed_report != first_report
      assert int(vm.succeed(f"systemctl show {TARGET} -p MainPID --value")) != target_pid

      vm.succeed(f"systemctl stop {HOST}")
      vm.succeed(f"mkdir -p /run/systemd/system/{HOST}.d")
      vm.succeed(f"printf '%b\\n' '[Service]\\nRestart=no' > {HOST_OVERRIDE}")
      vm.succeed("systemctl daemon-reload")

      # Replay old, validly signed bytes after the normal dependency chain
      # replaces the target. Host must reject that stale PID independently.
      vm.succeed(f"install -m 0400 {REPORT} {STALE_REPORT}")
      stale_report = vm.succeed(f"base64 -w0 {STALE_REPORT}").strip()
      stale_pid = struct.unpack_from(">I", base64.b64decode(stale_report), 152)[0]
      start_inspector(True)
      current_pid = int(vm.succeed(f"systemctl show {TARGET} -p MainPID --value"))
      assert current_pid != stale_pid
      vm.succeed(f"install -m 0400 {STALE_REPORT} {REPORT}")
      assert vm.succeed(f"base64 -w0 {REPORT}").strip() == stale_report
      vm.succeed(f"systemctl is-active --quiet {INSPECTOR}")
      start_host(False, "shifted target PID differs from the signed probe")
      vm.succeed(f"rm {STALE_REPORT}")
      start_inspector(True)

      # PID 1's current service policy is re-read by Host, not inferred from
      # the inspector's earlier signed report.
      override_target("[Service]\\nProtectSystem=full")
      assert vm.succeed(f"systemctl show {TARGET} -p ProtectSystem --value").strip() == "full"
      start_host(False, "shifted target filesystem policy is not strict")
      vm.succeed(f"rm {OVERRIDE}")
      vm.succeed("systemctl daemon-reload")
      start_inspector(True)

      vm.succeed(
          f"printf '%b\\n' '[Service]\\nRestart=no\\nSystemCallFilter=\\nSystemCallFilter=${widenedHostFilter}' > {HOST_OVERRIDE}"
      )
      vm.succeed("systemctl daemon-reload")
      widened_filter = vm.succeed(f"systemctl show {HOST} -p SystemCallFilter --value")
      assert "ptrace" in widened_filter.split(), widened_filter
      start_host(False, "PID 1 Host seccomp policy differs from the fixed profile")
      vm.succeed(
          f"printf '%b\\n' '[Service]\\nRestart=no\\nSystemCallErrorNumber=ENOSYS' > {HOST_OVERRIDE}"
      )
      vm.succeed("systemctl daemon-reload")
      start_host(False, "PID 1 Host seccomp policy differs from the fixed profile")
      vm.succeed(f"rm {HOST_OVERRIDE}")
      vm.succeed("systemctl daemon-reload")
      start_inspector(True)
      start_host(True)
      vm.succeed(f"systemctl stop {HOST}")

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
