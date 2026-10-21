# Exercises genuine ordinary funded preparation inside a disposable Linux VM.
{
  pkgs,
  lib,
}: let
  components = import ./phase4-funded-source-components.nix {inherit pkgs lib;};
  fixtures = import ./phase4-funded-source-fixtures.nix {inherit pkgs lib components;};
  inherit (components) support cli worker;
  workerClosure = worker.passthru.runtimeClosure;
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "crucible-funded-source-templates";
    # The old full-restore fixture declares a 4 GiB scene policy. This separate
    # VM has 2 GiB additional kernel/parent room; neither value certifies fit.
    memory = 6144;
    extraWritableMiB = 384;
    rootfsDeps = [
      support
      cli
      fixtures
      worker
      workerClosure
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
      pkgs.sed
    ];
    testScript = ''
      set -eu
      for option in PROC_CHILDREN CFS_BANDWIDTH MEMCG CGROUP_PIDS QUOTA QFMT_V2 QUOTACTL SECURITY_LANDLOCK SECCOMP_FILTER; do
        grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      test -r "/proc/$$/task/$$/children"
      test ! -e /etc/ld.so.preload
      test ! -L /etc/ld.so.preload
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/funded-source
      echo '+cpu +memory +pids' > /sys/fs/cgroup/funded-source/cgroup.subtree_control

      # Disk-backed project quota and state directories; no tmpfs substitute.
      mkdir -p /var/lib/funded-source
      truncate -s 256M /var/lib/funded-source/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /var/lib/funded-source/attempts.img
      mkdir /var/lib/funded-source/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /var/lib/funded-source/attempts.img /var/lib/funded-source/attempts
      for name in templates-a templates-b births-a births-b bad-pin cli; do
        mkdir -m 700 /var/lib/funded-source/attempts/run-$name
        mkdir -m 700 /var/lib/funded-source/attempts/state-$name
      done

      # Worker code roots plus installation/reference-graph metadata are actual
      # readonly mounts. No store-wide path or synthesized loader approval.
      while IFS= read -r root; do
        ${pkgs.util-linux}/bin/mount --bind "$root" "$root"
        ${pkgs.util-linux}/bin/mount -o remount,bind,ro "$root"
      done < ${workerClosure}/store-paths
      for root in ${worker} ${workerClosure}; do
        ${pkgs.util-linux}/bin/mount --bind "$root" "$root"
        ${pkgs.util-linux}/bin/mount -o remount,bind,ro "$root"
      done

      # These two fresh ordinary processes consume the exact same logical file
      # and actual host ELF. The actor derives its own operational Host token.
      consumer=${support}/bin/crucible-funded-source-templates-flight
      for name in templates-a templates-b; do
        if ! ${pkgs.coreutils}/bin/timeout -k 5 240 "$consumer" \
          ${fixtures}/$name/daemon.json ${fixtures}/$name/operational.json \
          ${fixtures}/support/configuration.json ${fixtures}/support/expected.json \
          templates > /var/lib/funded-source/$name.log 2>&1; then
          cat /var/lib/funded-source/$name.log
          exit 1
        fi
        cat /var/lib/funded-source/$name.log
        grep -Fxq PASS /var/lib/funded-source/$name.log
        grep -Fxq actual_command_twice_and_retained_world_credit=true /var/lib/funded-source/$name.log
        grep -Fxq terminal_namespace_absent_and_world_credit_released=true /var/lib/funded-source/$name.log
        grep -Fxq actual_small_policy_failure_and_spent_retry_retained=true /var/lib/funded-source/$name.log
      done
      first=$(sed -n 's/^consumer_pid=//p' /var/lib/funded-source/templates-a.log)
      second=$(sed -n 's/^consumer_pid=//p' /var/lib/funded-source/templates-b.log)
      case "$first:$second" in *[!0-9:]*|:|0:*|*:0) exit 1;; esac
      test -n "$first" && test -n "$second" && test "$first" != "$second"

      # These separate finite policies fund actual worker execution and parent
      # Birth assembly. Template authentication alone cannot satisfy this cut.
      for name in births-a births-b; do
        if ! ${pkgs.coreutils}/bin/timeout -k 5 240 "$consumer" \
          ${fixtures}/$name/daemon.json ${fixtures}/$name/operational.json \
          ${fixtures}/support/configuration.json ${fixtures}/support/expected.json \
          births > /var/lib/funded-source/$name.log 2>&1; then
          cat /var/lib/funded-source/$name.log
          exit 1
        fi
        cat /var/lib/funded-source/$name.log
        grep -Fxq PASS /var/lib/funded-source/$name.log
        grep -Fxq actual_three_worker_results_and_private_births_retained=true /var/lib/funded-source/$name.log
        grep -Fxq terminal_namespace_absent_and_world_credit_released=true /var/lib/funded-source/$name.log
      done
      first=$(sed -n 's/^consumer_pid=//p' /var/lib/funded-source/births-a.log)
      second=$(sed -n 's/^consumer_pid=//p' /var/lib/funded-source/births-b.log)
      case "$first:$second" in *[!0-9:]*|:|0:*|*:0) exit 1;; esac
      test -n "$first" && test -n "$second" && test "$first" != "$second"
      ${pkgs.coreutils}/bin/timeout -k 5 240 "$consumer" \
        ${fixtures}/bad-pin/daemon.json ${fixtures}/bad-pin/operational.json \
        ${fixtures}/support/configuration.json ${fixtures}/bad-pin/expected.json \
        failure > /var/lib/funded-source/bad-pin.log 2>&1
      cat /var/lib/funded-source/bad-pin.log
      grep -Fxq PASS /var/lib/funded-source/bad-pin.log
      grep -Fxq terminal_namespace_absent_and_world_credit_released=true /var/lib/funded-source/bad-pin.log

      # This separate default-feature component has its own host measurement.
      # Public Refused proves neither template success nor package qualification.
      program=${cli}/bin/crucible
      socket=/var/lib/funded-source/attempts/state-cli/node.sock
      ${pkgs.coreutils}/bin/timeout -k 5 240 "$program" node serve-complete-scene \
        --policy ${fixtures}/cli/daemon.json --operational-policy ${fixtures}/cli/operational.json \
        --installation ${fixtures}/cli/configuration.json --expected ${fixtures}/cli/expected.json \
        > /var/lib/funded-source/cli.log 2>&1 &
      monitor=$!
      daemon_pid=
      for tick in $(seq 1 500); do
        if test -S "$socket" && test -r /proc/$monitor/task/$monitor/children; then
          children=$(cat /proc/$monitor/task/$monitor/children)
          set -- $children
          test "$#" -eq 1
          daemon_pid=$1
          test "$(readlink /proc/$daemon_pid/exe)" = "$program"
          break
        fi
        sleep 0.01
      done
      test -n "$daemon_pid"
      for attempt in first spent; do
        if "$program" node complete-scene-prepare --socket "$socket" \
          > /var/lib/funded-source/cli-$attempt.log 2>&1; then
          exit 1
        fi
        grep -Fq 'node actor refused' /var/lib/funded-source/cli-$attempt.log
      done
      kill -TERM "$daemon_pid"
      wait "$monitor"
      test ! -e /var/lib/funded-source/attempts/state-cli/complete-scene
      test ! -L /var/lib/funded-source/attempts/state-cli/complete-scene
      ${pkgs.util-linux}/bin/umount /var/lib/funded-source/attempts
      echo same_configuration_two_actual_consumer_pids=true
      echo private_birth_construction_two_actual_consumer_pids=true
      echo first_failure_and_spent_retry_keep_credit_until_terminal_release=true
      echo default_feature_cli_public_refusal_twice_and_normal_shutdown=true
      echo controller_package_and_strict_acceptance=pending
      echo node_ready_capture_and_performance=unqualified
    '';
  }
