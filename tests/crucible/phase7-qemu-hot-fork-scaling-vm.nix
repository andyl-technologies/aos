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
  scenario = ./fixtures/e2e-determinism.scenario.toml;
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
          cargo build --frozen --offline --release \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-qemu --example crucible-qemu-live-hot-fork-child-stress
          cargo test --frozen --offline --release --no-run \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-daemon --lib > "$TMPDIR/messages.jsonl"
          daemon_test=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/messages.jsonl")
          test -f "$daemon_test"
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/examples/crucible-qemu-live-hot-fork-child-stress" \
            "$out/bin/qemu-hot-fork-stress"
          cp "$daemon_test" "$out/bin/crucible-daemon-scaling"
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
      pkgs.crucible
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.findutils
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
      for lane in source target; do
        setup_lane "$lane" 1073741824
      done
      for depth in 1 2 3; do
        setup_lane "depth-$depth-source" 536870912
        setup_lane "depth-$depth-target" 335544320
      done
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
        export CRUCIBLE_ATOMIC_WORLD_KERNEL="$kernel"
      done
      export CRUCIBLE_ATOMIC_WORLD_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
      export CRUCIBLE_ATOMIC_WORLD_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
      export CRUCIBLE_ATOMIC_WORLD_ROOT=${guest}/root.ext4
      export CRUCIBLE_ATOMIC_WORLD_SCENARIO=${scenario}
      export CRUCIBLE_ATOMIC_WORLD_ARTIFACTS=/tmp/artifacts
      export CRUCIBLE_ATOMIC_WORLD_CGROUP=/sys/fs/cgroup/crucible
      export CRUCIBLE_ATOMIC_WORLD_STORAGE=/tmp/attempts/run
      export CRUCIBLE_ATOMIC_WORLD_RUN_STATE=/tmp/run-state
      export CRUCIBLE_ATOMIC_WORLD_UID=65534
      export CRUCIBLE_ATOMIC_WORLD_GID=65534

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

      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically \
        /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_ready_millis=' /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_private_dirty_kib=' /tmp/daemon-scaling-result
      ${pkgs.grep}/bin/grep -Fq 'child_allocated_bytes=' /tmp/daemon-scaling-result
      run_exact_lib_test \
        crucible-daemon \
        qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_scales_across_three_semantic_template_depths \
        /tmp/depth-scaling-result
      ${pkgs.grep}/bin/grep -Fxq 'semantic_template_depth=3' /tmp/depth-scaling-result
      ${pkgs.grep}/bin/grep -Fxq \
        'nested_os_fork=forbidden-by-qemu-child-contract' /tmp/depth-scaling-result
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

      run_profile() {
        ram_mib="$1"
        siblings="$2"
        label="ram-$ram_mib-siblings-$siblings"
        # Forked guest RAM remains charged once while shared. The 3/2-RAM cap
        # leaves 128 MiB for QEMU metadata at the smallest profile and prevents
        # a complete second RAM image at the largest profile.
        memory_max=$((ram_mib * 1572864 + 134217728))
        setup_lane "$label" "$memory_max"
        ${pkgs.coreutils}/bin/timeout -k 15 $((300 + siblings * 2)) \
          ${flight}/bin/qemu-hot-fork-stress \
          ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
          ${pkgs.linux}/boot/vmlinuz-* \
          ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
          "/sys/fs/cgroup/crucible/$label" "/tmp/attempts/run/$label" \
          "$siblings" "$ram_mib" > "/tmp/$label.result"
        cat "/tmp/$label.result"
        ${pkgs.grep}/bin/grep -Fxq PASS "/tmp/$label.result"

        private_kib=$(${pkgs.gawk}/bin/awk -F= \
          '/^max_child_private_rss_kib=/{print $2}' "/tmp/$label.result")
        # One quarter of guest RAM plus 32 MiB is below full-RAM scaling at
        # every profile while covering the pinned platform's fixed overhead.
        private_limit_kib=$((ram_mib * 256 + 32768))
        [ "$private_kib" -le "$private_limit_kib" ]
        source_bytes=$(${pkgs.gawk}/bin/awk -F= \
          '/^source_allocated_bytes=/{print $2}' "/tmp/$label.result")
        allocated_bytes=$(${pkgs.gawk}/bin/awk -F= \
          '/^max_child_allocated_bytes=/{print $2}' "/tmp/$label.result")
        # Half the physical source allocation plus 16 MiB rejects a complete
        # disk-state clone while allowing branch-private metadata.
        disk_limit=$((source_bytes / 2 + 16777216))
        [ "$allocated_bytes" -le "$disk_limit" ]
        ${pkgs.gawk}/bin/awk -F= '/^ready_latency_ms=/{
          count = split($2, values, ",");
          for (i = 1; i <= count; i++) ordered[i] = values[i];
          asort(ordered);
          percentile_index = int((95 * count + 99) / 100);
          print ordered[percentile_index];
        }' "/tmp/$label.result" > "/tmp/$label.p95"
      }

      # Sixteen samples make the small-guest p95 a distribution rather than a
      # renamed single observation. Larger guests use fewer siblings so this
      # routine matrix stays bounded; the 10k profile below owns long churn.
      run_profile 64 16
      run_profile 256 4
      run_profile 512 1
      small_p95=$(cat /tmp/ram-64-siblings-16.p95)
      [ "$small_p95" -lt 100 ]

      # The expensive canonical profile executes ten thousand actual
      # fork/QMP-ready/kill/reap/resource-release cycles from one retained QEMU.
      setup_lane ten-thousand 536870912
      ${pkgs.coreutils}/bin/timeout -k 30 10800 \
        ${flight}/bin/qemu-hot-fork-stress \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${pkgs.linux}/boot/vmlinuz-* \
        ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
        /sys/fs/cgroup/crucible/ten-thousand \
        /tmp/attempts/run/ten-thousand 10000 128 \
        > /tmp/ten-thousand.result
      cat /tmp/ten-thousand.result
      ${pkgs.grep}/bin/grep -Fxq lifecycles=10000 /tmp/ten-thousand.result
      ${pkgs.grep}/bin/grep -Fxq source_threads_leaked=0 /tmp/ten-thousand.result
      ${pkgs.grep}/bin/grep -Fxq source_descriptors_leaked=0 /tmp/ten-thousand.result
      [ -z "$(${pkgs.findutils}/bin/find /sys/fs/cgroup/crucible/ten-thousand \
        -name cgroup.procs -exec ${pkgs.coreutils}/bin/cat {} \;)" ]

      cat /tmp/daemon-scaling-result \
        /tmp/depth-scaling-result \
        /tmp/ram-64-siblings-16.result \
        /tmp/ram-256-siblings-4.result \
        /tmp/ram-512-siblings-1.result \
        /tmp/ten-thousand.result > /tmp/hot-fork-scaling-measurements
      printf '%s\n' \
        PASS \
        'gate=gate:hot-fork-scaling' \
        'scope=production-native-qemu' \
        'ram_mib=64,256,512' \
        'sibling_lifecycles=16,4,1' \
        'semantic_template_depth=3' \
        'native_process_lifecycles=10000' \
        'pressure=cgroup-memory,pids,project-quota' \
        'nested_os_fork=forbidden-by-qemu-child-contract' \
        'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' \
        >> /tmp/hot-fork-scaling-measurements
      cat /tmp/hot-fork-scaling-measurements
      ${pkgs.util-linux}/bin/umount /tmp/attempts
      trap - EXIT HUP INT TERM
    '';
  }
