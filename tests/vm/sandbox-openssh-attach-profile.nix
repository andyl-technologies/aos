# Certificate/profile and root-monitor custody qualification; no execution I/O.
{
  lib,
  testing,
  pkgs,
}: let
  fixtures = pkgs.mkCargoPackage {
    pname = "aos-sandbox-openssh-attach-profile-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos-sandbox-agent.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-agent"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postInstall = ''
      mkdir -p "$out/bin"
      count=0
      for candidate in target/debug/deps/aos_sandbox_agent-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" "$out/bin/attach-profile-tests"
          count=$((count + 1))
        fi
      done
      test "$count" -eq 1
    '';
  };
in
  testing.mkVMTest {
    name = "sandbox-openssh-attach-profile";
    rootfsDeps = [fixtures pkgs.aos-sandbox-agent pkgs.openssh pkgs.coreutils pkgs.grep pkgs.iproute2];
    memory = 256;
    testScript = ''
      unset LD_LIBRARY_PATH
      # The headless init has no network manager. Both readiness and the real
      # SSH client need the kernel's initially-down loopback interface.
      ${pkgs.iproute2}/sbin/ip link set lo up
      chmod 0755 /run
      mkdir -p /usr/sbin /var/empty /run/sshd /home/aos_exec
      chmod 0755 /var/empty /run/sshd /home/aos_exec
      test "$(readlink -f /usr/sbin/sshd)" = ${pkgs.openssh}/sbin/sshd

      # The callback runs as the already selected non-root login account.
      # No new privileged account or execution-I/O bridge is created here.
      printf 'root:x:0:0:root:/root:${pkgs.bash}/bin/bash\naos_exec:x:1001:1001:execution:/home/aos_exec:${pkgs.bash}/bin/bash\nsshd:x:74:74:sshd:/var/empty:${pkgs.bash}/bin/bash\n' > /etc/passwd
      printf 'root:x:0:\naos_exec:x:1001:\nsshd:x:74:\n' > /etc/group
      printf 'root::0:0:99999:7:::\naos_exec::0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n' > /etc/shadow
      chmod 0600 /etc/shadow
      printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' > /etc/nsswitch.conf
      chmod 0644 /etc/passwd /etc/group /etc/nsswitch.conf

      export AOS_ATTACH_PROFILE_QUALIFICATION=1
      export AOS_ATTACH_PROFILE_GATE=${pkgs.aos-sandbox-agent}/bin/aos-sandbox-exec-gate
      export AOS_ATTACH_PROFILE_SSH=${pkgs.openssh}/bin/ssh
      export AOS_ATTACH_PROFILE_CHROOT=${pkgs.coreutils}/bin/chroot
      export AOS_ATTACH_PROFILE_SLEEP=${pkgs.coreutils}/bin/sleep
      export AOS_ATTACH_PROFILE_SSHD_SESSION=${pkgs.openssh}/libexec/sshd-session
      export AOS_ATTACH_PROFILE_PAM_DENY=${pkgs.linux-pam}/lib/security/pam_deny.so
      export AOS_ATTACH_PROFILE_PAM_PERMIT=${pkgs.linux-pam}/lib/security/pam_permit.so
      export AOS_ATTACH_PROFILE_BASH=${pkgs.bash}/bin/bash
      test_name=openssh_attach_certificate::qualification::packaged_sshd_enforces_profile_and_confined_original_ticket_relay
      ${fixtures}/bin/attach-profile-tests --ignored --exact --list "$test_name" \
        | ${pkgs.grep}/bin/grep -Fxq "$test_name: test"
      ${fixtures}/bin/attach-profile-tests --ignored --exact "$test_name" \
        --test-threads=1 --nocapture
    '';
  }
