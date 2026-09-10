# Real Guardian activation plus transient payload compilation and verification.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  incarnation = "61616161616161616161616161616161";
  runtimeUnit = "aos-sandbox-${incarnation}.service";
  guardian = "aos-lease-guard-${incarnation}";
  workspace = "/run/aos/sandbox-pins/workspaces/qualification";
  network = "/run/aos/sandbox-pins/netns/qualification";
  testName = "plan::kernel_tests::production_compiler_worker_launch_refresh_and_stop";
  guardianBrokerTestName = "broker::tests::guardian::root_guardian_apply_completes_bound_payload_and_replays_receipt";
  guardianCompensationTestName = "broker::tests::guardian::root_guardian_payload_failure_completes_exact_compensation";
  guardianRecoveredProofTestName = "broker::tests::guardian::root_guardian_recovers_payload_start_from_observation_only_proof";
  guardianRecoveredExpiredTestName = "broker::tests::guardian::root_guardian_recovered_proof_cannot_complete_after_lease_expiry";
  guardianBothAbsentRecoveryTestName = "broker::tests::guardian::root_guardian_recovery_commits_compensation_when_both_units_are_absent";
  guardianRecoveryRaceTestName = "broker::tests::guardian::root_guardian_recovery_never_restarts_payload_that_disappears_during_proof";
  guardianVerifiedPairTestName = "broker::tests::guardian::root_payload_verified_recovery_requires_live_fresh_guardian_pair";
  guardianReducerTestPrefix = "broker::tests::guardian::guardian_reducer_";
  stopProofWrongCgroupTestName = "worker::tests::stop_proof_rejects_recycled_leader_from_a_different_cgroup";
  guardianSystemdTestName = "broker::tests::guardian_systemd::production_worker_enforces_guardian_before_payload_across_restart_and_death";

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-host-worker-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-host --features kernel-tests"
    ];
    doCheck = true;
    cargoTestFlags = "-p aos-sandbox-host --lib";
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postBuild = ''
      mkdir worker-fixture

      cargo_target_dir=target
      if [ -n "''${CARGO_BUILD_TARGET:-}" ]; then
        cargo_target_dir="$cargo_target_dir/$CARGO_BUILD_TARGET"
      fi

      count=0
      for candidate in "$cargo_target_dir"/debug/deps/aos_sandbox_host-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" worker-fixture/aos-sandbox-host-worker-tests
          count=$((count + 1))
        fi
      done
      if [ "$count" -ne 1 ]; then
        echo "expected exactly one aos_sandbox_host unit-test executable under $cargo_target_dir/debug/deps, found $count" >&2
        exit 1
      fi
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 worker-fixture/aos-sandbox-host-worker-tests "$out/bin/"
    '';
  };

  qualificationInit = pkgs.mkDerivation {
    pname = "aos-host-worker-qualification-init";
    version = "1";
    src = null;
    # The compiled exec path is a runtime reference, not a build-time hint.
    runtimeDeps = [pkgs.systemd];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            -DAOS_QUALIFICATION_SYSTEMD='"${pkgs.systemd}/lib/systemd/systemd"' \
            ${../sandbox/nspawn-worker-init.c} -o qualification-init
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp qualification-init "$out/bin/"
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };

  payloadTarget = pkgs.writeTextFile {
    name = "aos-host-worker-payload-target";
    destination = "/default.target";
    text = ''
      [Unit]
      Description=Minimal payload for production worker qualification
      DefaultDependencies=no
      Requires=qualification.service
      After=qualification.service
    '';
  };
  payloadProcess = pkgs.writeTextFile {
    name = "aos-host-worker-payload-process";
    destination = "/bin/qualification-payload";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -euo pipefail
      generation=0
      if [ -f /var/qualification-generation ]; then
        read -r generation < /var/qualification-generation
      fi
      case "$generation" in
        0|1|2) ;;
        *) exit 1 ;;
      esac
      generation=$((generation + 1))
      printf '%s\n' "$generation" > /var/qualification-generation.tmp
      ${pkgs.coreutils}/bin/mv /var/qualification-generation.tmp /var/qualification-generation
      while :; do
        if [ -f /var/qualification-reboot ]; then
          ${pkgs.coreutils}/bin/rm /var/qualification-reboot
          exec ${pkgs.systemd}/bin/systemctl --no-block reboot
        fi
        ${pkgs.coreutils}/bin/sleep 0.05
      done
    '';
  };
  payloadService = pkgs.writeTextFile {
    name = "aos-host-worker-payload-service";
    destination = "/qualification.service";
    text = ''
      [Unit]
      Description=Retain the qualified payload execution
      DefaultDependencies=no

      [Service]
      Type=simple
      ExecStart=${payloadProcess}/bin/qualification-payload
    '';
  };
  root = pkgs.runCommand "aos-host-worker-payload-root" {} ''
    ${pkgs.grep}/bin/grep -aFq '${pkgs.systemd}/lib/systemd/systemd' \
      '${qualificationInit}/bin/qualification-init'
    mkdir -p "$out/etc/systemd/system" "$out/usr/lib" "$out/sbin" "$out/nix/store" "$out/var"
    cp ${payloadTarget}/default.target "$out/etc/systemd/system/default.target"
    cp ${payloadService}/qualification.service "$out/etc/systemd/system/qualification.service"
    ln -s ${qualificationInit}/bin/qualification-init "$out/sbin/init"
    printf 'NAME=AOS-host-worker-qualification\nID=aos-host-worker-qualification\n' > "$out/usr/lib/os-release"
    ln -s ../usr/lib/os-release "$out/etc/os-release"
    printf '${incarnation}\n' > "$out/etc/machine-id"
  '';

  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.systemd pkgs.iproute2 pkgs.nftables pkgs.util-linux];
      systemd.slices.aos-sandboxes.description = "Sandbox worker qualification runtimes";

      # The real guardian is a separate gate. This inert dependency permits the
      # production unit's BindsTo/After contract to be exercised without claiming
      # ownership-lease or network-expiry enforcement.
      systemd.services.${guardian} = {
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };

      systemd.services.aos-host-worker-qualification = {
        serviceConfig = {
          Type = "oneshot";
          TimeoutStartSec = 180;
          Environment = [
            "AOS_SANDBOX_WORKER_QUALIFICATION=1"
            "AOS_SANDBOX_QUALIFICATION_NSPAWN=${pkgs.systemd}/bin/systemd-nspawn"
            "AOS_SANDBOX_QUALIFICATION_GUARDIAN=${pkgs.aos-sandbox-guardian}/bin/aos-sandbox-guardian"
            "AOS_SANDBOX_QUALIFICATION_SYSTEMCTL=${pkgs.systemd}/bin/systemctl"
          ];
        };
        script = ''
          set -eu
          mkdir -p ${workspace} /run/aos/sandbox-pins/netns
          cp -a ${root}/. ${workspace}/
          ${pkgs.util-linux}/bin/mount --bind /nix/store ${workspace}/nix/store
          ${pkgs.util-linux}/bin/mount -o remount,bind,ro ${workspace}/nix/store
          ${pkgs.iproute2}/sbin/ip netns add aos-host-worker-qualification
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add table inet qualification'
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add chain inet qualification input { type filter hook input priority 0; policy drop; }'
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add chain inet qualification output { type filter hook output priority 0; policy drop; }'
          touch ${network}
          ${pkgs.util-linux}/bin/mount --bind /run/netns/aos-host-worker-qualification ${network}
          ${pkgs.systemd}/bin/systemctl start aos-sandboxes.slice
          unset LD_LIBRARY_PATH
          run_guardian_root_test() {
            selected_test=$1
            success_marker=$2
            test_log=$3
            if ! ${fixture}/bin/aos-sandbox-host-worker-tests --exact "$selected_test" \
              --test-threads=1 --nocapture > "$test_log" 2>&1; then
              ${pkgs.coreutils}/bin/cat "$test_log"
              exit 1
            fi
            ${pkgs.coreutils}/bin/cat "$test_log"
            ${pkgs.grep}/bin/grep -Fq "$success_marker" "$test_log"
          }
          guardian_log=/run/aos-guardian-broker-root-test
          if ! ${fixture}/bin/aos-sandbox-host-worker-tests --exact '${guardianBrokerTestName}' \
            --test-threads=1 --nocapture > "$guardian_log" 2>&1; then
            ${pkgs.coreutils}/bin/cat "$guardian_log"
            exit 1
          fi
          ${pkgs.coreutils}/bin/cat "$guardian_log"
          ${pkgs.grep}/bin/grep -Fq 'AOS_GUARDIAN_BROKER_ROOT_INTEGRATION_OK' "$guardian_log"
          compensation_log=/run/aos-guardian-compensation-root-test
          if ! ${fixture}/bin/aos-sandbox-host-worker-tests --exact '${guardianCompensationTestName}' \
            --test-threads=1 --nocapture > "$compensation_log" 2>&1; then
            ${pkgs.coreutils}/bin/cat "$compensation_log"
            exit 1
          fi
          ${pkgs.coreutils}/bin/cat "$compensation_log"
          ${pkgs.grep}/bin/grep -Fq 'AOS_GUARDIAN_COMPENSATION_ROOT_INTEGRATION_OK' "$compensation_log"
          run_guardian_root_test \
            '${guardianRecoveredProofTestName}' \
            'AOS_GUARDIAN_RECOVERED_PROOF_ROOT_OK' \
            /run/aos-guardian-recovered-proof-root-test
          run_guardian_root_test \
            '${guardianRecoveredExpiredTestName}' \
            'AOS_GUARDIAN_RECOVERED_EXPIRED_ROOT_OK' \
            /run/aos-guardian-recovered-expired-root-test
          run_guardian_root_test \
            '${guardianBothAbsentRecoveryTestName}' \
            'AOS_GUARDIAN_BOTH_ABSENT_RECOVERY_ROOT_OK' \
            /run/aos-guardian-both-absent-recovery-root-test
          run_guardian_root_test \
            '${guardianRecoveryRaceTestName}' \
            'AOS_GUARDIAN_RECOVERY_RACE_ROOT_OK' \
            /run/aos-guardian-recovery-race-root-test
          run_guardian_root_test \
            '${guardianVerifiedPairTestName}' \
            'AOS_GUARDIAN_VERIFIED_PAIR_RECOVERY_ROOT_OK' \
            /run/aos-guardian-verified-pair-root-test
          guardian_reducer_log=/run/aos-guardian-reducer-root-tests
          if ! ${fixture}/bin/aos-sandbox-host-worker-tests '${guardianReducerTestPrefix}' \
            --test-threads=1 --nocapture > "$guardian_reducer_log" 2>&1; then
            ${pkgs.coreutils}/bin/cat "$guardian_reducer_log"
            exit 1
          fi
          ${pkgs.coreutils}/bin/cat "$guardian_reducer_log"
          ${pkgs.grep}/bin/grep -Fq '5 passed' "$guardian_reducer_log"
          run_guardian_root_test \
            '${stopProofWrongCgroupTestName}' \
            'AOS_STOP_PROOF_WRONG_CGROUP_OK' \
            /run/aos-stop-proof-wrong-cgroup-root-test
          guardian_systemd_log=/run/aos-guardian-systemd-root-test
          if ! ${fixture}/bin/aos-sandbox-host-worker-tests --ignored --exact '${guardianSystemdTestName}' \
            --test-threads=1 --nocapture > "$guardian_systemd_log" 2>&1; then
            ${pkgs.coreutils}/bin/cat "$guardian_systemd_log"
            exit 1
          fi
          ${pkgs.coreutils}/bin/cat "$guardian_systemd_log"
          ${pkgs.grep}/bin/grep -Fq 'AOS_GUARDIAN_SYSTEMD_COMBINED_OK' "$guardian_systemd_log"
          ${pkgs.coreutils}/bin/rm -f ${workspace}/var/qualification-generation ${workspace}/var/qualification-reboot
          ${fixture}/bin/aos-sandbox-host-worker-tests --ignored --exact '${testName}' --list \
            > /run/aos-host-worker-selected-tests
          ${pkgs.grep}/bin/grep -Fx '${testName}: test' /run/aos-host-worker-selected-tests
          exec ${fixture}/bin/aos-sandbox-host-worker-tests --ignored --exact '${testName}' \
            --test-threads=1 --nocapture
        '';
      };
    }
  ];
in {
  name = "sandbox-host-worker";
  timeout = 300;
  machines.vm = {inherit system;};
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    try:
        vm.succeed("systemctl start aos-host-worker-qualification.service", timeout=200)
        vm.fail("systemctl is-active --quiet ${runtimeUnit}")
    finally:
        print(vm.execute("journalctl -u aos-host-worker-qualification.service -u ${runtimeUnit} --no-pager")[1].decode("utf-8", errors="replace"))
        print(vm.execute("journalctl -k -n 100 --no-pager")[1].decode("utf-8", errors="replace"))
        print(vm.execute("${pkgs.grep}/bin/grep 'type=SECCOMP' /var/log/audit/audit.log")[1].decode("utf-8", errors="replace"))
        vm.execute("systemctl stop ${runtimeUnit} ${guardian}.service aos-sandbox-71717171717171717171717171717171.service aos-lease-guard-71717171717171717171717171717171.service aos-sandbox-75757575757575757575757575757575.service aos-lease-guard-75757575757575757575757575757575.service")
  '';
}
