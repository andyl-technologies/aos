# Measures production daemon adoption and the native QEMU fork/reap path under
# cgroup and project-quota pressure. The VM retains every raw sample alongside
# the structural CPERF-3 assertions.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.hotForkScaling.rawGate",
  taskIds ? [],
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  scenario = pkgs.writeTextFile {
    name = "crucible-e2e-determinism-scenario";
    destination = "/scenario.toml";
    text = builtins.readFile ./fixtures/e2e-determinism.scenario.toml;
  };
  flight = pkgs.mkDerivation {
    pname = "crucible-qemu-hot-fork-scaling-flight";
    version = "0";
    src = source;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
    ];
    runtimeDeps = [pkgs.openssl];
    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo test --frozen --offline --release --no-run \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-api -p crucible-qemu -p crucible-daemon --lib \
            > "$TMPDIR/messages.jsonl"
          daemon_test=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/messages.jsonl")
          test -f "$daemon_test"
          mkdir -p "$out/bin"
          cp "$daemon_test" "$out/bin/crucible-daemon-scaling"
          for package in crucible_api crucible_qemu; do
            binary=$(jq -r --arg package "$package" \
              'select(.reason == "compiler-artifact" and .target.name == $package and .profile.test == true and .executable != null) | .executable' \
              "$TMPDIR/messages.jsonl")
            test -f "$binary"
            cp "$binary" "$out/bin/$package-clone-cost"
          done
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "crucible-qemu-hot-fork-scaling";
    memory = 6144;
    rootfsDeps = [
      flight
      guest
      scenario
      pkgs.crucible
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
      pkgs.gawk
    ];
    testScript = ''
      set -eu
      cleanup_attempt_mount() {
        ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
      }
      trap cleanup_attempt_mount EXIT HUP INT TERM

      for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
        ${pkgs.grep}/bin/grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

      truncate -s 6G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
        -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      mkdir -m 700 /tmp/attempts/run /tmp/run-state /tmp/artifacts
      ${pkgs.crucible}/bin/crucible-e2e-determinism-scenario \
        --populate-store /tmp/artifacts

      setup_lane() {
        lane="$1"
        memory_max="$2"
        mkdir "/sys/fs/cgroup/crucible/$lane"
        echo '+cpu +memory +pids' \
          > "/sys/fs/cgroup/crucible/$lane/cgroup.subtree_control"
        echo "$memory_max" > "/sys/fs/cgroup/crucible/$lane/memory.max"
        echo 64 > "/sys/fs/cgroup/crucible/$lane/pids.max"
        mkdir -m 700 "/tmp/attempts/run/$lane"
      }

      # Production daemon ownership: the exact lifecycle factory performs the
      # source freeze, child fork/adoption, measurement, shutdown, reconciliation,
      # and source recovery while cgroup and quota owners remain live.
      # Each lane owns three 256-MiB QEMU guests plus resident device state.
      for lane in source target; do
        setup_lane "$lane" 2147483648
      done
      setup_lane child-ready-source 1073741824
      setup_lane child-ready-target 1073741824
      for depth in 1 2 3; do
        setup_lane "depth-$depth-source" 536870912
        setup_lane "depth-$depth-target" 335544320
      done
      for memory_mib in 64 256 512; do
        setup_lane "ram-$memory_mib-source" 1073741824
        setup_lane "ram-$memory_mib-target" 1073741824
      done
      setup_lane production-stress-source 1073741824
      setup_lane production-stress-target 1073741824
      setup_lane performance-checkpoint-source 1073741824
      setup_lane performance-replay-genesis 1073741824
      for index in 0 1 2; do
        setup_lane "performance-source-$index" 1073741824
        setup_lane "performance-hot-$index" 1073741824
        setup_lane "performance-exact-$index" 1073741824
        setup_lane "performance-replay-oracle-$index" 1073741824
      done

      mkdir -m 700 /tmp/checkpoints
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
        export CRUCIBLE_ATOMIC_WORLD_KERNEL="$kernel"
      done
      export CRUCIBLE_ATOMIC_WORLD_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
      export CRUCIBLE_ATOMIC_WORLD_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
      export CRUCIBLE_ATOMIC_WORLD_ROOT=${guest}/root.ext4
      export CRUCIBLE_ATOMIC_WORLD_SCENARIO=${scenario}/scenario.toml
      export CRUCIBLE_ATOMIC_WORLD_ARTIFACTS=/tmp/artifacts
      export CRUCIBLE_ATOMIC_WORLD_CGROUP=/sys/fs/cgroup/crucible
      export CRUCIBLE_ATOMIC_WORLD_STORAGE=/tmp/attempts/run
      export CRUCIBLE_ATOMIC_WORLD_RUN_STATE=/tmp/run-state
      export CRUCIBLE_ATOMIC_WORLD_UID=65534
      export CRUCIBLE_ATOMIC_WORLD_GID=65534
      export CRUCIBLE_ATOMIC_WORLD_CHECKPOINTS=/tmp/checkpoints

      run_exact_lib_test() {
        package="$1"
        name="$2"
        result="$3"
        case "$package" in
          crucible-daemon) binary=${flight}/bin/crucible-daemon-scaling ;;
          *) echo "unknown library test package $package" >&2; return 1 ;;
        esac

        if listing=$("$binary" --ignored --exact "$name" --list 2>&1); then
          :
        else
          status=$?
          printf '%s\n' "$listing" >&2
          return "$status"
        fi
        count=$(printf '%s\n' "$listing" \
          | ${pkgs.grep}/bin/grep -Fxc "$name: test" || true)
        if [ "$count" -ne 1 ]; then
          printf '%s\n' "$listing" >&2
          echo "expected exactly one $package library test named $name, found $count" >&2
          return 1
        fi

        if output=$(${pkgs.coreutils}/bin/timeout -k 30 1800 \
          "$binary" --ignored --exact "$name" --nocapture 2>&1); then
          :
        else
          status=$?
          printf '%s\n' "$output" >&2
          return "$status"
        fi
        printf '%s\n' "$output" > "$result"
        printf '%s\n' "$output"
        printf '%s\n' "$output" | ${pkgs.grep}/bin/grep -Fq \
          'test result: ok. 1 passed; 0 failed; 0 ignored;'
      }

      run_host_clone_test() {
        package="$1"
        name="$2"
        result="$3"
        binary=${flight}/bin/"$package"-clone-cost
        if listing=$("$binary" --exact "$name" --list 2>&1); then
          :
        else
          status=$?
          printf '%s\n' "$listing" >&2
          return "$status"
        fi
        count=$(printf '%s\n' "$listing" \
          | ${pkgs.grep}/bin/grep -Fxc "$name: test" || true)
        if [ "$count" -ne 1 ]; then
          printf '%s\n' "$listing" >&2
          echo "expected exactly one $package library test named $name, found $count" >&2
          return 1
        fi

        if ${pkgs.coreutils}/bin/timeout -k 30 120 \
          "$binary" --exact "$name" --nocapture > "$result" 2>&1; then
          :
        else
          status=$?
          cat "$result" >&2
          return "$status"
        fi
        if ! ${pkgs.grep}/bin/grep -Fq \
          'test result: ok. 1 passed; 0 failed; 0 ignored;' "$result"; then
          cat "$result" >&2
          echo "expected one passing $package library test named $name" >&2
          return 1
        fi
        cat "$result"
      }

      require_exact_test_marker() {
        expected="$1"
        result="$2"
        if ${pkgs.gawk}/bin/awk -v expected="$expected" '
          $0 == expected { found = 1 }
          /^test [^[:space:]]+ \.\.\. / && $NF == expected { found = 1 }
          END { exit !found }
        ' "$result"; then
          return 0
        fi
        cat "$result" >&2
        echo "missing exact test marker $expected" >&2
        return 1
      }

      # libtest joins the first captured line to its `test ...` prefix.
      printf '%s\n' 'test fixture::clone ... host_continuation_siblings=64' \
        > /tmp/test-marker-fixture
      require_exact_test_marker host_continuation_siblings=64 /tmp/test-marker-fixture
      if require_exact_test_marker host_continuation_siblings=6 /tmp/test-marker-fixture \
        > /dev/null 2>&1; then
        echo 'test marker parser accepted a partial value' >&2
        exit 1
      fi

      run_host_clone_test \
        crucible_api \
        vm_lifecycle::hot_fork::tests::host_continuation_clone_cost_is_bounded_across_siblings \
        /tmp/host-clone-cost-result
      require_exact_test_marker host_continuation_siblings=64 /tmp/host-clone-cost-result
      ${pkgs.grep}/bin/grep -Fxq 'host_immutable_object_bytes=33554432' /tmp/host-clone-cost-result
      ${pkgs.grep}/bin/grep -Fxq 'host_shared_backing_copies=1' /tmp/host-clone-cost-result
      ${pkgs.grep}/bin/grep -Fxq 'host_clone_private_growth_limit_kib=65536' /tmp/host-clone-cost-result
      run_host_clone_test \
        crucible_qemu \
        production_fault_runtime::checkpoint_codec::tests::fault_checkpoint_clone_cost_keeps_mutable_ledgers_private \
        /tmp/fault-clone-cost-result
      require_exact_test_marker fault_checkpoint_siblings=64 /tmp/fault-clone-cost-result
      ${pkgs.grep}/bin/grep -Fxq 'qemu_authentication_map_copies=1' /tmp/fault-clone-cost-result
      ${pkgs.grep}/bin/grep -Fxq \
        'child_private_ledgers=network-adapter,pending-qemu-events' /tmp/fault-clone-cost-result

      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically \
        /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_ready_millis=' /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_private_dirty_kib=' /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_allocated_bytes=' /tmp/daemon-scaling-result
      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_single_vm_child_ready_p95_is_below_100_milliseconds \
        /tmp/child-ready-p95-result
      ${pkgs.grep}/bin/grep -Fxq \
        'child_ready_reference=single-vm-64mib-1vcpu' /tmp/child-ready-p95-result
      ${pkgs.grep}/bin/grep -Fxq 'child_ready_sample_count=20' /tmp/child-ready-p95-result
      ${pkgs.grep}/bin/grep -Fxq \
        'child_ready_p95_limit_ns=100000000' /tmp/child-ready-p95-result
      ${pkgs.gawk}/bin/awk -F= '
        $1 == "child_ready_samples_ns" {
          sample_lines++;
          count = split($2, raw, ",");
          if (count != 20) bad = 1;
          for (i = 1; i <= count; i++) {
            if (raw[i] !~ /^[0-9]+$/) bad = 1;
            samples[i] = raw[i] + 0;
          }
          if (count == 20) {
            asort(samples);
            # Nearest-rank p95 of 20 measurements is the 19th ordered value.
            computed_p95 = samples[19];
          }
        }
        $1 == "child_ready_p95_ns" {
          p95_lines++;
          if ($2 !~ /^[0-9]+$/) bad = 1;
          reported_p95 = $2 + 0;
        }
        END {
          if (sample_lines != 1 || p95_lines != 1 || bad ||
              computed_p95 != reported_p95 || computed_p95 >= 100000000) exit 1;
        }' /tmp/child-ready-p95-result
      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_scales_across_three_semantic_template_depths \
        /tmp/depth-scaling-result
      ${pkgs.grep}/bin/grep -Fxq 'semantic_template_depth=3' /tmp/depth-scaling-result
      ${pkgs.grep}/bin/grep -Fxq \
        'descendant_template_generations=3' /tmp/depth-scaling-result
      ${pkgs.gawk}/bin/awk -F= \
        '$1 == "descendant_process_generations" {
          count = split($2, generation, ",");
          if (count == 3 && generation[2] == generation[1] + 1 &&
              generation[3] == generation[2] + 1) found = 1;
        }
        END { exit found ? 0 : 1 }' /tmp/depth-scaling-result
      for depth in 1 2 3; do
        depth_private=$(${pkgs.gawk}/bin/awk -F= \
          -v key="template_depth_''${depth}_private_rss_kib" \
          '$1 == key {print $2}' /tmp/depth-scaling-result)
        depth_disk=$(${pkgs.gawk}/bin/awk -F= \
          -v key="template_depth_''${depth}_allocated_bytes" \
          '$1 == key {print $2}' /tmp/depth-scaling-result)
        depth_source_disk=$(${pkgs.gawk}/bin/awk -F= \
          -v key="template_depth_''${depth}_source_allocated_bytes" \
          '$1 == key {print $2}' /tmp/depth-scaling-result)
        # CPERF-3 rejects a full private RAM or disk copy. The fixed additions
        # cover the current QEMU allocator, page-table, and overlay metadata.
        depth_disk_limit=$((depth_source_disk / 2 + 16777216))
        [ "$depth_private" -le 98304 ]
        [ "$depth_disk" -le "$depth_disk_limit" ]
      done

      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_scales_across_three_guest_memory_sizes \
        /tmp/memory-scaling-result
      ${pkgs.grep}/bin/grep -Fxq \
        'guest_memory_profiles_mib=64,256,512' /tmp/memory-scaling-result

      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_whole_world_survives_ten_thousand_lifecycles_without_leaks \
        /tmp/production-stress-result
      ${pkgs.grep}/bin/grep -Fxq \
        'production_whole_world_lifecycles=10000' /tmp/production-stress-result
      ${pkgs.grep}/bin/grep -Fxq \
        'qemu_child_pairing=exact_source_boundary' /tmp/production-stress-result
      ${pkgs.grep}/bin/grep -Fxq 'source_threads_leaked=0' /tmp/production-stress-result
      ${pkgs.grep}/bin/grep -Fxq 'source_descriptors_leaked=0' /tmp/production-stress-result

      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_meets_whole_world_performance_ratchets \
        /tmp/performance-ratchet-result
      for evidence in \
        exact_restore_corpus_size=3 \
        setup_speedup_minimum=5x \
        steady_execution_overhead_limit_percent=10 \
        known_dirty_guest_pages=1024 \
        memory_metrics=VmPTE,VmData,AnonHugePages,numa_maps \
        multi_node_launch_model=max-plus-bounded-orchestration; do
        ${pkgs.grep}/bin/grep -Fxq "$evidence" /tmp/performance-ratchet-result
      done

      cat /tmp/host-clone-cost-result \
        /tmp/fault-clone-cost-result \
        /tmp/daemon-scaling-result \
        /tmp/child-ready-p95-result \
        /tmp/depth-scaling-result \
        /tmp/memory-scaling-result \
        /tmp/production-stress-result \
        /tmp/performance-ratchet-result > /tmp/hot-fork-scaling-measurements
      printf '%s\n' \
        PASS \
        'gate=gate:hot-fork-scaling' \
        'scope=production-native-qemu' \
        'performance_owner=production-whole-world' \
        'guest_memory_profiles_mib=64,256,512' \
        'production_whole_world_lifecycles=10000' \
        'semantic_template_depth=3' \
        'standalone_stress_path=removed' \
        'pressure=cgroup-memory,pids,project-quota' \
        'descendant_template_generations=3' \
        'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' \
        >> /tmp/hot-fork-scaling-measurements
      cat /tmp/hot-fork-scaling-measurements
      ${pkgs.util-linux}/bin/umount /tmp/attempts
      trap - EXIT HUP INT TERM
    '';
  }
