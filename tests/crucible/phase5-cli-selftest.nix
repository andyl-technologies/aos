{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSelftest",
  taskIds ? ["T-CLI-8"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  helpSurface = builtins.readFile ../../crates/crucible-cli/tests/help_surface.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-8 packaged production selftest evidence";
        needle = "Completed under `checks.crucible.phase5.cliSelftest`";
      }
      {
        label = "T-CLI-8 unmodified stock-kernel evidence";
        needle = "packaged production CLI against the unmodified stock Linux kernel";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI selftest completion note";
        needle = "`T-CLI-8` is completed through `checks.crucible.phase5.cliSelftest`";
      }
      {
        label = "phase5 direct packaged production selftest execution";
        needle = "process invocation of the packaged production\n  `crucible --campaign-deployment /tmp/executor.toml selftest` process";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/help_surface.rs" helpSurface [
      {
        label = "production selftest excludes test-double options";
        needle = "cli_production_selftest_help_excludes_test_double_options";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI dev-tests against canonical gate catalog";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "selftest gates flag";
        needle = "gates: Option<String>";
      }
      {
        label = "test-double-only selftest qemu flag";
        needle = ''          #[cfg(any(test, feature = "test-double"))]
              #[arg(long, action = ArgAction::SetTrue)]
              with_qemu: bool'';
      }
      {
        label = "selftest corpus flag";
        needle = "corpus: Option<PathBuf>";
      }
      {
        label = "built-in corpus selftest gate subset";
        needle = "BUILT_IN_CORPUS_SELFTEST_GATES";
      }
      {
        label = "real qemu selftest gate subset";
        needle = "REAL_QEMU_SELFTEST_GATES";
      }
      {
        label = "canonical gate validation";
        needle = "CANONICAL_GATE_NAMES";
      }
      {
        label = "canonical gate catalog drift test";
        needle = "cli_selftest_canonical_gate_names_match_harness_catalog";
      }
      {
        label = "dev-test canonical gate catalog source";
        needle = "crucible_harness::canonical_gates()";
      }
      {
        label = "selftest gate planner";
        needle = "fn plan_selftest_gates";
      }
      {
        label = "per-gate selftest report";
        needle = "struct SelftestGateReport";
      }
      {
        label = "real-QEMU gates execute the live backend";
        needle = "probe.run_probe(backend)?";
      }
      {
        label = "real-QEMU selftest icount evidence";
        needle = "live_qemu_icount";
      }
      {
        label = "per-gate output row";
        needle = "gate={} status={} runner={}";
      }
      {
        label = "built-in corpus runner";
        needle = "crucible::built_in_example_corpus";
      }
      {
        label = "corpus manifest loader";
        needle = "fn verify_selftest_corpus_manifest";
      }
      {
        label = "corpus manifest fixture resolver";
        needle = "fn verify_selftest_fixture_by_name";
      }
      {
        label = "qemu discovery runner";
        needle = "fn require_selftest_qemu_backend";
      }
      {
        label = "typed selftest host deployment";
        needle = "ProductionLiveQemuProbeRunner::new(cli.campaign_deployment.clone())";
      }
      {
        label = "qemu identity report field";
        needle = "qemu_build_id: Option<String>";
      }
      {
        label = "runner report field";
        needle = "SelftestGateRunner";
      }
      {
        label = "selected gates test";
        needle = "gate:replay-oracle";
      }
      {
        label = "empty gate entry rejection";
        needle = "empty selftest gate component must be rejected";
      }
      {
        label = "duplicate gate rejection";
        needle = "duplicate selftest gate must be rejected";
      }
      {
        label = "test-double qemu gate requires flag";
        needle = "real-QEMU selftest gate must require --with-qemu";
      }
      {
        label = "test-double with-qemu discovery error";
        needle = "selftest --with-qemu without artifacts must fail discovery";
      }
      {
        label = "gate validation before qemu discovery";
        needle = "invalid selftest gate must be rejected before qemu discovery";
      }
      {
        label = "with-qemu exit code";
        needle = "assert_eq!(error.exit_code(), 4);";
      }
      {
        label = "positive qemu selftest report";
        needle = "qemu_report.gates.iter().all";
      }
      {
        label = "file-backed corpus test";
        needle = "selftest-corpus.txt";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "production-hidden selftest qemu flag";
        needle = ''#[cfg_attr(not(any(test, feature = "test-double")), arg(hide = true))]'';
      }
      {
        label = "stale qemu runner blocker";
        needle = "real-QEMU selftest gate runner tracked by T-CLI-8";
      }
      {
        label = "stale extended runner blocker";
        needle = "real-QEMU and extended gate runners remain tracked by T-CLI-8";
      }
      {
        label = "hidden selftest cgroup root";
        needle = "CRUCIBLE_QEMU_" + "CGROUP_ROOT";
      }
      {
        label = "hidden selftest run root";
        needle = "CRUCIBLE_QEMU_" + "RUN_ROOT";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI selftest check";
        needle = "cliSelftest = import ./phase5-cli-selftest.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI selftest check failed:\n${builtins.concatStringsSep "\n" failures}"
  else let
    sourceChecks = pkgs.mkDerivation {
      pname = "crucible-phase5-cli-selftest-source";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
        pkgs.pkg-config
        pkgs.sqlite
      ];
      runtimeDeps = [pkgs.sqlite];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

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
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-cli-selftest";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-selftest-target" \
              -p crucible-cli \
              cli_selftest \
              -- --test-threads=1

            mkdir -p "$out"
            touch "$out/passed"
          '';
        }
      ];
    };
    deployment = builtins.toFile "selftest-packaged-executor.toml" ''
      schema = "crucible.campaign-packaged-executor"
      version = 2
      cgroup_root = "/sys/fs/cgroup/crucible"
      run_root = "/tmp/attempts/run"
      attempt_namespace = "cli-selftest"
      first_project_id = 32000
      project_id_count = 1
      child_user_id = 65534
      child_group_id = 65534
      maximum_tasks = 64
      maximum_inodes = 4096
      finish_timeout_ms = 15000
      maximum_slots = 1
      maximum_vcpus = 1
      maximum_resident_bytes = 536870912
      maximum_disk_bytes = 2147483648
      maximum_execution_quanta = 10000
      maximum_checkpoint_bytes = 1073741824
      worker_count = 1
      host_architecture = "${pkgs.stdenv.hostPlatform.parsed.cpu.name}"
      qemu_profile = "deterministic-tcg-v1"

      [operations]
      listener_workers = 4
      pending_connections = 16
      requests_per_connection = 4096
      accept_poll_interval_ms = 10
      exchange_read_timeout_ms = 30000
      exchange_write_timeout_ms = 30000
      runtime_poll_interval_ms = 100
      planner_scan_limit = 1024
      planner_input_bytes = 16777216
      planner_fuel = 1025
      executor_scan_limit = 1024
      worker_slots_per_campaign = 1
    '';
    testing = import ../../lib/testing {inherit pkgs lib;};
    vmTest = testing.mkVMTest {
      name = "crucible-phase5-cli-selftest-live-qemu";
      memory = 2048;
      rootfsDeps = [
        pkgs.coreutils
        pkgs.crucible
        pkgs.e2fsprogs
        pkgs.grep
        pkgs.jq
        pkgs.sed
        pkgs.util-linux
        deployment
      ];
      testScript = ''
        set -eu

        cleanup_attempt_mount() {
          ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
        }

        trap cleanup_attempt_mount EXIT HUP INT TERM
        mkdir -p /sys/fs/cgroup
        ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
        echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
        mkdir /sys/fs/cgroup/crucible
        echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

        truncate -s 4G /tmp/attempts.img
        ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
          -E quotatype=prjquota /tmp/attempts.img
        mkdir /tmp/attempts
        ${pkgs.util-linux}/bin/mount -o loop,prjquota \
          /tmp/attempts.img /tmp/attempts
        mkdir -m 700 /tmp/attempts/run
        install -m 600 ${deployment} /tmp/executor.toml

        unset CRUCIBLE_CAMPAIGN_DEPLOYMENT
        if ${pkgs.crucible}/bin/crucible selftest \
          > /tmp/missing-deployment.out 2> /tmp/missing-deployment.err; then
          echo 'production selftest accepted missing guarded host authority'
          exit 1
        else
          missing_deployment_status="$?"
        fi
        test "$missing_deployment_status" -eq 4
        ${pkgs.grep}/bin/grep -Fq \
          'load guarded selftest host deployment: local QEMU execution requires guarded campaign host authority' \
          /tmp/missing-deployment.err

        ${pkgs.crucible}/bin/crucible \
          --artifact-dir /tmp/crucible-cli-selftest-artifacts \
          --campaign-deployment /tmp/executor.toml \
          selftest > /tmp/production-selftest.out

        ${pkgs.jq}/bin/jq -r \
          'select(.kind == "selftest_gate") | .summary' \
          /tmp/production-selftest.out > /tmp/selftest-gate-rows

        validate_selftest_gate_rows() {
          rows="$1"
          row_pattern='^gate=(gate:single-vm-fingerprint|gate:any-guest|gate:qemu-inert) status=PASS runner=qemu corpus=0 runs-per-entry=5 qemu=blake3:[0-9a-f]{64} live-icount=[1-9][0-9]* live-fingerprint=blake3:[0-9a-f]{64}$'
          test "$(${pkgs.coreutils}/bin/wc -l < "$rows")" -eq 3 || return 1
          test "$(${pkgs.grep}/bin/grep -Ec "$row_pattern" "$rows" || true)" -eq 3 \
            || return 1
          for gate in \
            gate:single-vm-fingerprint \
            gate:any-guest \
            gate:qemu-inert
          do
            test "$(${pkgs.grep}/bin/grep -Ec "^gate=$gate " "$rows" || true)" -eq 1 \
              || return 1
          done
        }

        validate_selftest_gate_rows /tmp/selftest-gate-rows

        cp /tmp/selftest-gate-rows /tmp/duplicate-rows
        ${pkgs.coreutils}/bin/head -n 1 /tmp/selftest-gate-rows >> /tmp/duplicate-rows
        if validate_selftest_gate_rows /tmp/duplicate-rows; then
          echo 'selftest evidence accepted a duplicate gate row'
          exit 1
        fi

        ${pkgs.sed}/bin/sed \
          '0,/live-fingerprint=blake3:[0-9a-f]\{64\}/s//live-fingerprint=blake3:0/' \
          /tmp/selftest-gate-rows > /tmp/short-digest-rows
        if validate_selftest_gate_rows /tmp/short-digest-rows; then
          echo 'selftest evidence accepted a short fingerprint digest'
          exit 1
        fi

        cp /tmp/selftest-gate-rows /tmp/non-pass-rows
        echo 'gate=gate:extra status=FAIL runner=qemu corpus=0 runs-per-entry=5 qemu=blake3:0000000000000000000000000000000000000000000000000000000000000000 live-icount=1 live-fingerprint=blake3:0000000000000000000000000000000000000000000000000000000000000000' \
          >> /tmp/non-pass-rows
        if validate_selftest_gate_rows /tmp/non-pass-rows; then
          echo 'selftest evidence accepted an extra non-PASS gate row'
          exit 1
        fi

        cat /tmp/production-selftest.out

        ${pkgs.util-linux}/bin/umount /tmp/attempts
        trap - EXIT HUP INT TERM
      '';
    };
  in
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-selftest";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils sourceChecks vmTest];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cp "${vmTest}/serial.log" "$out/vm-serial.log"
            cat > "$out/result" <<'RESULT'
            PASS
            check=$ATTR_PATH
            tasks=$TASK_IDS
            open_tasks=$OPEN_TASK_IDS
            status=complete
            evidence_scope=packaged-production-cli-live-qemu-vm
            component=crucible-cli
            selftest=production-process-three-live-qemu-gates
            guest_kernel=unmodified-stock-linux
            corpus_manifest=true
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
