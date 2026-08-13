# default.nix — ANDYL OS
#
# The single entry point for everything AOS: library, packages, systems,
# modules, and checks. The flake wraps this for Nix flake consumers and
# adds dev-only things (devShell, formatter).
#
# Usage:
#   nix-build -A pkgs.coreutils                     Build a package
#   nix-build -A stdenv                              Build the production stdenv
#   nix-build -A systems.server.build.toplevel       Build the server system
#   nix-build -A systems.server.checks.boot-basics   Run a module check
#   nix-build -A systems.server.checks.system-boot   Run a system-level check
#   nix-build -A checks                              Run all tests
#   nix-build -A checks.eval                         Run evaluation checks only
#
# Architecture:
#   Check derivations are produced inside the module system via
#   modules/base/checks.nix, which transforms system.checks specs
#   into system.build.checks derivations. Each system variant
#   (server, edge) gets its own set of checks accessible as
#   systems.<name>.checks.<check-name>.
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules (including tests)
#   systems/ — Golden image definitions (auto-discovered)
{
  system ? builtins.currentSystem,
  crossSystem ? null,
}: let
  lib = import ./lib {
    inherit system;
    bash = stdenv.bash;
  };
  buildPlatform = lib.platform;
  hostPlatform =
    if crossSystem != null
    then lib.mkPlatform crossSystem
    else buildPlatform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  stdenv = import ./stdenv {
    inherit buildPlatform hostPlatform;
    targetPlatform = hostPlatform;
  };

  # All packages are built hermetically from source using only stdenv.
  pkgs = import ./pkgs {inherit lib stdenv;};

  # Auto-discovered module list.
  modules = import ./modules;

  # Assemble the in-image, eval-only base library for every
  # system. See `lib/build/base-lib.nix`.
  mkBaseLib = import ./lib/build/base-lib.nix {
    inherit lib pkgs;
    system = hostPlatform.system;
  };

  # Build a system from a system definition module (or list of modules).
  #
  # Accepts three calling conventions:
  #   mkSystem ./path.nix                              — single module path
  #   mkSystem [ ./a.nix ./b.nix ]                     — list of modules
  #   mkSystem { modules = [...]; specialArgs = {}; }   — full attrset
  mkSystem = args: let
    moduleList =
      if builtins.isList args
      then args
      else if builtins.isAttrs args && args ? modules
      then args.modules
      else [args];
    specialArgs =
      if builtins.isAttrs args && args ? specialArgs
      then args.specialArgs
      else {};
    systemName =
      if builtins.isAttrs args && args ? systemName
      then args.systemName
      else "system";
    # The on-host resolver supplies the verified `host.nix`
    # store path here as an operator-provenance module, so its bare defs are
    # lifted to the reserved priority-75 band (see `lib/modules.nix`
    # `operatorModules`). Defaults `[]` — no caller sets it yet, so every
    # existing system evaluates identically.
    operatorModules =
      if builtins.isAttrs args && args ? operatorModules
      then args.operatorModules
      else [];
    packageModules =
      if builtins.isAttrs args && args ? packageModules
      then args.packageModules
      else [];
    systemModules = builtins.filter builtins.isPath moduleList;
    # Determine the resolved image ABI from the complete caller module list.
    # The base library bundles only source-backed system modules, so without
    # carrying this value explicitly an inline image override would leave the
    # runtime image and its evaluator library on different ABIs.
    moduleAbi =
      (lib.evalModules {
        modules =
          modules
          ++ moduleList
          ++ [
            {
              aos.config.evalAtBoot = {
                baseLib = "/nix/store/00000000000000000000000000000000-aos-base-lib-probe";
                baseLibAbiHash = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "0") 64)}";
              };
            }
          ];
        inherit pkgs lib specialArgs operatorModules packageModules;
      })
      .config
      .aos
      .system
      .moduleAbi;
    baseLib = mkBaseLib {
      baseModules = modules;
      inherit systemModules systemName moduleAbi;
    };
  in
    lib.evalModules {
      modules =
        modules
        ++ moduleList
        ++ [
          {
            aos.config.evalAtBoot = {
              inherit baseLib;
              baseLibAbiHash = baseLib.passthru.abiHash;
            };
          }
        ];
      inherit pkgs lib specialArgs operatorModules packageModules;
    };

  # Auto-discover system definitions from ./systems/*.nix
  discoverSystems = let
    entries = builtins.readDir ./systems;
    nixFiles = builtins.filter (
      name:
        entries.${name}
        == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
    ) (builtins.attrNames entries);
  in
    builtins.listToAttrs (
      map (name: {
        name = lib.removeSuffix ".nix" name;
        value = let
          variant = ./systems + "/${name}";
          evaluated = mkSystem {
            modules = [variant];
            systemName = lib.removeSuffix ".nix" name;
          };
        in {
          config = evaluated.config;
          options = evaluated.options;
          # Re-expose `extendModules` so callers holding a discovered system
          # (e.g. the fleet harness, which bakes per-VM identity via
          # `environment.etc`) can overlay a fragment without rebuilding the
          # module list. Inherits this variant's baseLib wiring.
          inherit (evaluated) extendModules;
          build = {
            toplevel = evaluated.config.system.build.toplevel;
            kernel = evaluated.config.system.build.kernel;
            initrd = evaluated.config.system.build.initrd;
            image = evaluated.config.system.build.image;
          };
          # VM test derivations — produced inside the module system by
          # modules/base/checks.nix, not by external collection scripts.
          checks = evaluated.config.system.build.checks;
        };
      })
      nixFiles
    );

  # ---------------------------------------------------------------------------
  # Test infrastructure
  # ---------------------------------------------------------------------------

  # The default system used for eval/build checks and package integration tests.
  serverSystem = mkSystem ./systems/server.nix;

  # Testing harness (headless mode for package integration tests)
  testing = import ./lib/testing {inherit pkgs lib;};

  prefixAttrs = prefix: attrs:
    builtins.listToAttrs (
      map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # ---------------------------------------------------------------------------
  # APM/APR VM tests (headless Firecracker, registry + tracking + packages)
  # ---------------------------------------------------------------------------
  apmTests = import ./tests/vm/apm {inherit testing pkgs;};

  # ---------------------------------------------------------------------------
  # Package integration checks (Firecracker-based, defined on packages)
  # ---------------------------------------------------------------------------
  packageChecks = builtins.foldl' (
    acc: name: let
      pkg = pkgs.${name};
    in
      if builtins.isAttrs pkg && pkg ? checks && builtins.isFunction pkg.checks
      then
        acc
        // prefixAttrs name (
          pkg.checks {
            inherit testing pkgs;
            self = pkg;
          }
        )
      else acc
  ) {} (builtins.attrNames pkgs);

  packagesWithExpose =
    lib.filterAttrs (_: p: builtins.isAttrs p && p ? expose) pkgs;

  packageExposeLifecycleCheck = import ./lib/testing/package-expose-lifecycle.nix {
    inherit pkgs lib mkSystem testing;
  };
  packageFirewallReloadCheck = import ./lib/testing/package-firewall-reload.nix {
    inherit pkgs mkSystem testing;
  };
  packagePresetCheck = import ./lib/testing/package-preset.nix {
    inherit pkgs mkSystem testing;
  };
  packageTestHttpServerCheck = import ./lib/testing/package-test-http-server.nix {
    inherit pkgs lib mkSystem testing;
  };
  apmInstallAtBootCheck = import ./lib/testing/apm-install-at-boot.nix {
    inherit pkgs mkSystem testing;
  };
  selinuxBaseCheck = import ./lib/testing/selinux-base.nix {
    inherit pkgs mkSystem testing;
  };

  # Stdenv cross-cutting integration check
  stdenvChecks = {
    cross-cutting-c-pipeline = testing.mkVMTest {
      name = "cross-cutting-c-pipeline";
      rootfsDeps = [pkgs.binutils];
      testScript = ''
        cat > /tmp/pipeline.c << 'EOF'
        #include <stdio.h>
        int add(int a, int b) { return a + b; }
        int main(void) {
            int result = add(3, 4);
            printf("3 + 4 = %d\n", result);
            if (result != 7) return 1;
            return 0;
        }
        EOF

        echo "==> Stage 1: Preprocessing (gcc -E)"
        gcc -E /tmp/pipeline.c -o /tmp/pipeline.i

        echo "==> Stage 2: Compile to assembly (gcc -S)"
        gcc -S /tmp/pipeline.i -o /tmp/pipeline.s

        echo "==> Stage 3: Assemble to object (gcc -c)"
        gcc -c /tmp/pipeline.s -o /tmp/pipeline.o

        echo "==> Stage 4: Link to binary"
        gcc /tmp/pipeline.o -o /tmp/pipeline

        echo "==> Stage 5: Run the binary"
        /tmp/pipeline
        echo "C compilation pipeline: PASS"
      '';
    };
  };

  # ---------------------------------------------------------------------------
  # Fleet tests (multi-VM, inherently span multiple systems)
  # ---------------------------------------------------------------------------
  fleetHarness = import ./lib/testing/fleet.nix {inherit pkgs lib;};

  discoverFleetTests = let
    fleetSpec = import ./lib/testing/fleet-spec.nix {inherit lib pkgs;};

    entries = builtins.readDir ./tests/fleet;
    fleetFiles = builtins.filter (
      n:
        entries.${n}
        == "regular"
        && builtins.match ".*\\.nix" n != null
        && builtins.substring 0 1 n != "_"
    ) (builtins.attrNames entries);

    loadSpec = filename: let
      specModule = import (./tests/fleet + "/${filename}");
      availableArgs = {
        inherit lib pkgs mkSystem;
        inherit (testing) dataUrl;
        systems = discoverSystems;
      };
      raw = specModule (
        lib.filterAttrs (name: _: builtins.hasAttr name (builtins.functionArgs specModule))
        availableArgs
      );
      eval = lib.evalModules {
        modules = [
          {options.spec = lib.mkOption {type = fleetSpec.fleetSpecType;};}
          {config.spec = raw;}
        ];
      };
    in
      eval.config.spec;
  in
    builtins.listToAttrs (
      map (filename: {
        name = lib.removeSuffix ".nix" filename;
        value = fleetHarness.mkFleetTest (loadSpec filename);
      })
      fleetFiles
    );

  crucibleChecksBase = import ./tests/crucible {inherit pkgs lib;};

  # T-PKG-15: the shared Crucible VM/fleet check substrate. It assembles the
  # whole Crucible closure (patched QEMU + plugin + CLI + kernel + fixtures) as
  # hermetic inputs and runs the built CLI under TCG with NO `kvm` system
  # feature ([PKG-29], [PKG-30], spec §26.8). Both the e2e-determinism fleet
  # check and the real-VM performance checks ride this same runner.
  crucibleFleetRunner = import ./tests/crucible/_fleet-runner.nix {inherit pkgs lib;};

  crucibleFleetChecks = {
    # gate:e2e-determinism as a real AOS VM/fleet check ([PKG-29], [PKG-30]).
    # It builds the entire Crucible closure hermetically and EXECUTES the built
    # `crucible` CLI end to end over the built-in adversarial multi-node,
    # fault-injected example corpus (happy-path, partition-recovery,
    # crash-restart, and the fault-campaign family) under the hostile
    # host-condition matrix (`--adversarial`), bisecting the first divergence
    # (`--bisect`) and asserting bit-identical reductions — the representative
    # multi-VM, fault-injected + reproduce scenario of §26.8. The phase7 e2e
    # gate (in-process determinism proof of the same scenario) is consumed as a
    # precondition so this fleet check advances only behind a green harness.
    #
    # Each independent reduction launches the closure-owned patched QEMU and
    # production plugin under TCG before the session-level comparison.
    crucible-e2e-determinism = let
      e2eGate = crucibleChecks.phase7.gates.e2eDeterminism.rawGate;
    in
      crucibleFleetRunner.mkCrucibleFleetCheck {
        name = "crucible-e2e-determinism";
        gateResults = [e2eGate];
        runPhaseScript = ''
          # The phase7 e2e gate must be green before the fleet scenario runs.
          grep -q '^PASS$' "${e2eGate}/result"
          grep -q '^gate=gate:e2e-determinism$' "${e2eGate}/result"
          grep -q '^fleet_check_surface=checks.fleet.crucible-e2e-determinism$' "${e2eGate}/result"

          crucible_bin="$CRUCIBLE/bin/crucible"

          # Run the representative multi-VM, fault-injected scenario end to end
          # over each built-in adversarial example, under the hostile
          # host-condition matrix, bisecting the first divergence. The JSONL
          # stream emits one `independent_reduction` event per (run x hostile
          # profile) and a `final_outcome` with `status=passed`; a non-passing
          # reduction exits the CLI non-zero and fails the check.
          for scenario in \
            happy-path.scn \
            partition-recovery.scn \
            crash-restart.scn \
            fault-campaign.fam
          do
            verify_out="$FLEET_WORKDIR/verify-$scenario.out"
            "$crucible_bin" \
              --backend qemu \
              --seed 31 \
              --store "$FLEET_STORE" \
              --artifact-dir "$FLEET_ARTIFACTS" \
              verify "$scenario" \
              --runs 2 \
              --adversarial \
              --bisect \
              > "$verify_out"

            # The scenario passed end to end under the adversarial matrix.
            grep -q '"kind":"final_outcome".*subcommand=verify status=passed' "$verify_out"

            # It actually ran under the hostile host-condition matrix (more than
            # one adversarial profile) and every independent reduction is
            # bit-identical — the same canonical_log across all profiles. A
            # single distinct canonical_log among the reductions proves the
            # scenario reproduced bit-identically across adversarial hosts.
            reductions="$(grep -c '"kind":"independent_reduction"' "$verify_out")"
            test "$reductions" -ge 2
            distinct_logs="$(
              grep '"kind":"independent_reduction"' "$verify_out" \
                | grep -o 'canonical_log=[^ ]*' \
                | sort -u \
                | wc -l
            )"
            test "$distinct_logs" -eq 1
          done
        '';
        resultLines = [
          "gate=gate:e2e-determinism"
          "source_check=checks.crucible.phase7.gates.e2eDeterminism"
          "e2e_gate_result=${e2eGate}/result"
          "fleet_surface=true"
          "scenario=adversarial-multi-node-fault-injected-corpus"
          "scenario_corpus=happy-path.scn,partition-recovery.scn,crash-restart.scn,fault-campaign.fam"
          "adversarial_matrix=hostile-host-condition-profiles"
          "reproduce=verify-reduction-bisection"
          "cli_backend=qemu-tcg-live-probe-plus-deterministic-session"
          "live_qemu_per_reduction=true"
          "lib_testing_runner=tests/crucible/_fleet-runner.nix"
          "tcg_only_vm_runner=crucible-cli-verify-adversarial-bisect"
        ];
      };
    # The real-process performance discharge for RFC-0010 §25 ([PERF-3],
    # [PERF-12], [PERF-13], [PERF-14], [PERF-27]): the deterministic
    # `gate:perf-bench` asserts the cost-model structure and host-independent
    # ratios; this fleet check supplies reference-host wall-clock numbers by
    # timing hermetic `crucible --backend qemu` processes. Every invocation
    # launches the closure-owned patched QEMU and production plugin under TCG
    # against the AOS-built kernel/root fixture before its session workload.
    crucible-perf = let
      perfGate = crucibleChecks.phase7.gates.perfBench.rawGate;
      savevmLoadvmGate = crucibleChecks.phase0.s3SavevmLoadvm;
    in
      crucibleFleetRunner.mkCrucibleFleetCheck {
        name = "crucible-perf";
        gateResults = [perfGate savevmLoadvmGate];
        runPhaseScript = ''
          # The modeled perf-bench gate must be green before the fleet numbers
          # are captured: the ratchet compares fleet numbers against baselines
          # the modeled gate already holds structurally.
          grep -q '^PASS$' "${perfGate}/result"
          grep -q '^gate=gate:perf-bench$' "${perfGate}/result"

          crucible_bin="$CRUCIBLE/bin/crucible"
          scenario="happy-path.scn"

          run_once() {
            # One real CLI process execution with a live QEMU/plugin probe.
            "$crucible_bin" \
              --backend qemu \
              --seed 31 \
              --store "$FLEET_STORE" \
              --artifact-dir "$FLEET_ARTIFACTS" \
              verify "$scenario" --runs 2 \
              > "$1" 2>&1
          }

          now_ns() { date +%s%N; }

          # --- Throughput ([PERF-13]): scenarios per wall-clock second over a
          # fixed sequential batch of real CLI process runs. ---
          batch=8
          t_start=$(now_ns)
          i=0
          while [ "$i" -lt "$batch" ]; do
            run_once "$FLEET_WORKDIR/thr-$i.out"
            grep -q '"kind":"final_outcome".*status=passed' "$FLEET_WORKDIR/thr-$i.out"
            i=$((i + 1))
          done
          t_end=$(now_ns)
          seq_ms=$(( (t_end - t_start) / 1000000 ))
          [ "$seq_ms" -gt 0 ] || seq_ms=1
          # scenarios per hour = batch * 3600_000 / seq_ms (integer).
          throughput_per_hour=$(( batch * 3600000 / seq_ms ))
          available_cores="$(nproc)"
          [ "$available_cores" -gt 0 ] || available_cores=1

          # --- Parallelism proxy ([PERF-3]): real host speedup of N concurrent
          # CLI processes versus the sequential batch. More cores must not make
          # the same work slower; the realized speedup is reported, never
          # asserted against an absolute target on a shared builder. ---
          p_start=$(now_ns)
          j=0
          while [ "$j" -lt "$batch" ]; do
            run_once "$FLEET_WORKDIR/par-$j.out" &
            j=$((j + 1))
          done
          wait
          p_end=$(now_ns)
          par_ms=$(( (p_end - p_start) / 1000000 ))
          [ "$par_ms" -gt 0 ] || par_ms=1
          j=0
          while [ "$j" -lt "$batch" ]; do
            grep -q '"kind":"final_outcome".*status=passed' "$FLEET_WORKDIR/par-$j.out"
            j=$((j + 1))
          done
          # Realized speedup x100 (integer): sequential_ms * 100 / parallel_ms.
          speedup_x100=$(( seq_ms * 100 / par_ms ))
          parallel_workers="$batch"
          if [ "$parallel_workers" -gt "$available_cores" ]; then
            parallel_workers="$available_cores"
          fi
          throughput_per_core_hour=$(( batch * 3600000 / (par_ms * parallel_workers) ))
          # Structural assertion: concurrency must not slow the identical work
          # down by more than a generous margin (parallel is never > 3x the
          # sequential wall-clock). This catches a real concurrency pathology
          # without pinning an absolute speedup on a noisy shared host.
          test "$par_ms" -le $(( seq_ms * 3 ))

          # --- Logical fleet sweep ([PERF-27]): run 1, 2, 4, and 8 independent
          # explorer-host processes against the shared content-addressed store.
          # The live ratio assertion requires at least 50% of ideal scaling
          # until available host cores saturate; the sweep also records
          # aggregate/per-core throughput and per-host store growth.
          fleet_sweep="$FLEET_WORKDIR/fleet-sweep.txt"
          : > "$fleet_sweep"
          one_host_per_hour=0
          for hosts in 1 2 4 8; do
            store_line_before="$(du -sk "$FLEET_STORE")"
            store_kib_before="''${store_line_before%%	*}"
            fleet_start="$(now_ns)"
            host=0
            while [ "$host" -lt "$hosts" ]; do
              run_once "$FLEET_WORKDIR/fleet-$hosts-$host.out" &
              host=$((host + 1))
            done
            wait
            fleet_end="$(now_ns)"
            host=0
            while [ "$host" -lt "$hosts" ]; do
              grep -q '"kind":"final_outcome".*status=passed' \
                "$FLEET_WORKDIR/fleet-$hosts-$host.out"
              host=$((host + 1))
            done
            store_line_after="$(du -sk "$FLEET_STORE")"
            store_kib_after="''${store_line_after%%	*}"
            fleet_ms=$(( (fleet_end - fleet_start) / 1000000 ))
            [ "$fleet_ms" -gt 0 ] || fleet_ms=1
            fleet_per_hour=$(( hosts * 3600000 / fleet_ms ))
            active_host_cores="$hosts"
            if [ "$active_host_cores" -gt "$available_cores" ]; then
              active_host_cores="$available_cores"
            fi
            fleet_per_core_hour=$((fleet_per_hour / active_host_cores))
            if [ "$hosts" -eq 1 ]; then
              one_host_per_hour="$fleet_per_hour"
            elif [ "$hosts" -le "$available_cores" ]; then
              # Before host-core saturation, aggregate throughput must retain
              # at least half of ideal linear scaling from the live one-host
              # baseline. This is deliberately a ratio, not an absolute
              # wall-clock threshold.
              minimum_linear=$((one_host_per_hour * hosts / 2))
              test "$fleet_per_hour" -ge "$minimum_linear"
            fi
            store_delta_kib=$((store_kib_after - store_kib_before))
            store_per_host_kib=$((store_delta_kib / hosts))
            {
              echo "fleet_hosts_''${hosts}_wall_ms=$fleet_ms"
              echo "fleet_hosts_''${hosts}_scenarios_per_hour=$fleet_per_hour"
              echo "fleet_hosts_''${hosts}_scenarios_per_core_hour=$fleet_per_core_hour"
              echo "fleet_hosts_''${hosts}_store_kib_per_host=$store_per_host_kib"
            } >> "$fleet_sweep"
          done

          # --- Restore latency ([PERF-12]): the Phase-0 live QEMU corpus
          # measures snapshot-load through the runnable `cont` acknowledgement.
          # The production thin-checkpoint fallback is measured here by
          # replaying an artifact whose prefix was produced by a live QEMU run.
          loadvm_boot_ms=
          loadvm_cpu_timer_ms=
          loadvm_mid_io_ms=
          while IFS='=' read -r key value; do
            case "$key" in
              boot_window_restore_to_runnable_ms) loadvm_boot_ms="$value" ;;
              cpu_timer_restore_to_runnable_ms) loadvm_cpu_timer_ms="$value" ;;
              mid_io_restore_to_runnable_ms) loadvm_mid_io_ms="$value" ;;
            esac
          done < "${savevmLoadvmGate}/result"
          test -n "$loadvm_boot_ms"
          test -n "$loadvm_cpu_timer_ms"
          test -n "$loadvm_mid_io_ms"

          set +e
          "$crucible_bin" \
            --backend qemu --seed 31 \
            --store "$FLEET_STORE" --artifact-dir "$FLEET_ARTIFACTS" \
            run "$scenario" --max-quanta 1 \
            > "$FLEET_WORKDIR/replay-source.out" 2>&1
          replay_source_status=$?
          set -e
          test "$replay_source_status" -eq 2
          grep -q '"kind":"final_outcome".*status=timeout' \
            "$FLEET_WORKDIR/replay-source.out"
          set -- "$FLEET_ARTIFACTS"/repro-timeout-*.crucible
          test "$#" -eq 1
          test -s "$1"
          replay_source="$1"
          r_start=$(now_ns)
          "$crucible_bin" \
            --backend qemu --seed 31 \
            --store "$FLEET_STORE" --artifact-dir "$FLEET_ARTIFACTS" \
            replay "$replay_source" \
            > "$FLEET_WORKDIR/replay.out" 2>&1
          r_end=$(now_ns)
          grep -q '"kind":"final_outcome".*status=passed' "$FLEET_WORKDIR/replay.out"
          restore_ms=$(( (r_end - r_start) / 1000000 ))
          restore_source=thin-replay-from-live-qemu-artifact

          # --- Idle compression ([PERF-2], real): the same scenario at the
          # QEMU-backed workflow runs in bounded wall-clock; record it. ---
          idle_ms=$seq_ms

          {
            echo "throughput_per_hour=$throughput_per_hour"
            echo "throughput_per_core_hour=$throughput_per_core_hour"
            echo "available_cores=$available_cores"
            echo "parallel_workers=$parallel_workers"
            echo "sequential_batch_ms=$seq_ms"
            echo "parallel_batch_ms=$par_ms"
            echo "realized_speedup_x100=$speedup_x100"
            echo "restore_latency_ms=$restore_ms"
            echo "restore_source=$restore_source"
            echo "loadvm_boot_window_restore_ms=$loadvm_boot_ms"
            echo "loadvm_cpu_timer_restore_ms=$loadvm_cpu_timer_ms"
            echo "loadvm_mid_io_restore_ms=$loadvm_mid_io_ms"
            echo "idle_batch_ms=$idle_ms"
            echo "batch_size=$batch"
          } > "$FLEET_WORKDIR/perf-numbers.txt"
          cat "$fleet_sweep" >> "$FLEET_WORKDIR/perf-numbers.txt"
          cat "$FLEET_WORKDIR/perf-numbers.txt"
        '';
        resultLines = [
          "gate=gate:perf-bench"
          "source_check=checks.crucible.phase7.gates.perfBench"
          "perf_gate_result=${perfGate}/result"
          "fleet_surface=true"
          "measurement_scope=real-cli-process-with-live-qemu-tcg-probe"
          "real_guest_boot=closure-owned-qemu-plugin-kernel-root"
          "cli_backend=qemu-tcg-live-probe-plus-deterministic-session"
          "terminal_icount=16000000"
          "throughput_per_hour=$throughput_per_hour"
          "throughput_per_core_hour=$throughput_per_core_hour"
          "available_cores=$available_cores"
          "parallel_workers=$parallel_workers"
          "sequential_batch_ms=$seq_ms"
          "parallel_batch_ms=$par_ms"
          "realized_speedup_x100=$speedup_x100"
          "restore_latency_ms=$restore_ms"
          "restore_source=$restore_source"
          "loadvm_boot_window_restore_ms=$loadvm_boot_ms"
          "loadvm_cpu_timer_restore_ms=$loadvm_cpu_timer_ms"
          "loadvm_mid_io_restore_ms=$loadvm_mid_io_ms"
          "idle_batch_ms=$idle_ms"
          "batch_size=$batch"
          "$(cat \"$fleet_sweep\")"
          "metric_throughput=real-process-wall-clock-batch [PERF-13]"
          "metric_parallelism=real-process-concurrent-speedup [PERF-3]"
          "metric_restore_latency=live-qmp-loadvm-plus-thin-replay-fallback [PERF-12]"
          "metric_coverage_ips=checks.crucible.phase0.coverageOverhead [PERF-14]"
          "metric_fleet_sweep=logical-host-concurrency-on-reference-runner [PERF-27]"
          "modeled_gate=checks.crucible.phase7.gates.perfBench"
          "lib_testing_runner=tests/crucible/_fleet-runner.nix"
        ];
      };
    crucible-distributed-continuous-exploration = let
      fleetStore = pkgs.crucible-fleet-store;
      explorer = pkgs.crucible;
      e2eGate = crucibleChecks.phase7.gates.e2eDeterminism.rawGate;
      fleetStoreGate = crucibleChecks.phase7.crucibleFleetStore;
      sharedDagStoreGate = crucibleChecks.phase7.crucibleSharedDagStore;
      frontierLeaseGate = crucibleChecks.phase7.crucibleFrontierLeases;
      fourLayerDedupGate = crucibleChecks.phase7.crucibleFourLayerDedup;
      campaignManifestGate = crucibleChecks.phase7.crucibleCampaignManifest;
      campaignSeedingGate = crucibleChecks.phase7.crucibleCampaignSeeding;
      campaignStorageBoundingGate = crucibleChecks.phase7.crucibleCampaignStorageBounding;
      campaignProvenanceGate = crucibleChecks.phase7.crucibleCampaignProvenance;
      determinismGuardrailGate = crucibleChecks.phase7.crucibleDeterminismGuardrail;
      fleetEquivalenceGate = crucibleChecks.phase7.gates.fleetEquivalence.rawGate;
      campaignContinuityGate = crucibleChecks.phase7.gates.campaignContinuity.rawGate;
    in
      pkgs.mkDerivation {
        pname = "crucible-fleet-distributed-continuous-exploration-surface";
        version = "0";
        src = null;

        buildDeps = [
          pkgs.coreutils
          pkgs.grep
          fleetStore
          explorer
          e2eGate
          fleetStoreGate
          sharedDagStoreGate
          frontierLeaseGate
          fourLayerDedupGate
          campaignManifestGate
          campaignSeedingGate
          campaignStorageBoundingGate
          campaignProvenanceGate
          determinismGuardrailGate
          fleetEquivalenceGate
          campaignContinuityGate
        ];

        phases = [
          {
            name = "check-distributed-continuous-exploration-surface";
            script = ''
              set -eu

              result="${e2eGate}/result"
              grep -q '^PASS$' "$result"
              grep -q '^gate=gate:e2e-determinism$' "$result"

              fleet_store_result="${fleetStoreGate}/result"
              grep -q '^PASS$' "$fleet_store_result"
              grep -q '^package=pkgs.crucible-fleet-store$' "$fleet_store_result"
              grep -q '^tcg_only=true$' "$fleet_store_result"
              grep -q '^kvm_required=false$' "$fleet_store_result"

              shared_dag_store_result="${sharedDagStoreGate}/result"
              grep -q '^PASS$' "$shared_dag_store_result"
              grep -q '^tasks=T-DCE-1$' "$shared_dag_store_result"
              grep -q '^shared_store_backend=SharedDagStore$' "$shared_dag_store_result"
              grep -q '^concurrent_put=idempotent$' "$shared_dag_store_result"

              frontier_lease_result="${frontierLeaseGate}/result"
              grep -q '^PASS$' "$frontier_lease_result"
              grep -q '^tasks=T-DCE-2$' "$frontier_lease_result"
              grep -q '^claim_lease=ttl-hint$' "$frontier_lease_result"
              grep -q '^stale_claim_lock=reclaimable$' "$frontier_lease_result"
              grep -q '^hash_affinity=priority-only$' "$frontier_lease_result"

              four_layer_dedup_result="${fourLayerDedupGate}/result"
              grep -q '^PASS$' "$four_layer_dedup_result"
              grep -q '^tasks=T-DCE-3$' "$four_layer_dedup_result"
              grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$' "$four_layer_dedup_result"
              grep -q '^coverage_map_admission=compare-and-merge$' "$four_layer_dedup_result"
              grep -q '^coverage_map_repair=entry-markers-before-fingerprint$' "$four_layer_dedup_result"
              grep -q '^reduction_fingerprint=shared-prune$' "$four_layer_dedup_result"

              campaign_manifest_result="${campaignManifestGate}/result"
              grep -q '^PASS$' "$campaign_manifest_result"
              grep -q '^tasks=T-DCE-4$' "$campaign_manifest_result"
              grep -q '^campaign_manifest=content-addressed$' "$campaign_manifest_result"
              grep -q '^campaign_head=cas-advanced$' "$campaign_manifest_result"
              grep -q '^campaign_head_lock=advisory-head-file$' "$campaign_manifest_result"
              grep -q '^campaign_head_log=append-only-checksummed$' "$campaign_manifest_result"
              grep -q '^manifest_root_objects=required$' "$campaign_manifest_result"
              grep -q '^lost_cas=bookkeeping-only$' "$campaign_manifest_result"
              grep -q '^merge_roots=materialized-objects$' "$campaign_manifest_result"

              campaign_seeding_result="${campaignSeedingGate}/result"
              grep -q '^PASS$' "$campaign_seeding_result"
              grep -q '^tasks=T-DCE-5$' "$campaign_seeding_result"
              grep -q '^campaign_seed=prior-corpus$' "$campaign_seeding_result"
              grep -q '^campaign_seed_artifact=self-contained$' "$campaign_seeding_result"
              grep -q '^campaign_seed_replay=bit-identical$' "$campaign_seeding_result"
              grep -q '^coverage_ratchet=grow-only-union-crdt$' "$campaign_seeding_result"
              grep -q '^coverage_ratchet_monotone=true$' "$campaign_seeding_result"
              grep -q '^coverage_crdt=commutative-associative-idempotent$' "$campaign_seeding_result"
              grep -q '^coverage_novelty=against-accumulated-map$' "$campaign_seeding_result"
              grep -q '^findings_ledger=cross-run-grow-only$' "$campaign_seeding_result"
              grep -q '^findings_ledger_dedup=content-addressed$' "$campaign_seeding_result"
              grep -q '^finding_replay=bit-identical-from-ledger$' "$campaign_seeding_result"

              campaign_storage_bounding_result="${campaignStorageBoundingGate}/result"
              grep -q '^PASS$' "$campaign_storage_bounding_result"
              grep -q '^tasks=T-DCE-6$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_roots=manifest-roots$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_unpinned=swept-candidate$' "$campaign_storage_bounding_result"
              grep -q '^campaign_gc_value=cache-only$' "$campaign_storage_bounding_result"
              grep -q '^fat_to_thin_eviction=value-preserved$' "$campaign_storage_bounding_result"
              grep -q '^thin_checkpoint_source=parent-schedule-delta$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention=deterministic-seeded-cap$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention_authorized=explicit-policy$' "$campaign_storage_bounding_result"
              grep -q '^corpus_retention_reproducible=true$' "$campaign_storage_bounding_result"
              grep -q '^findings_ledger_retention=never-evict$' "$campaign_storage_bounding_result"

              campaign_provenance_result="${campaignProvenanceGate}/result"
              grep -q '^PASS$' "$campaign_provenance_result"
              grep -q '^tasks=T-PKG-22$' "$campaign_provenance_result"
              grep -q '^provenance_key=campaign_provenance_key$' "$campaign_provenance_result"
              grep -q '^refusal=RefuseCrossProvenanceReuse$' "$campaign_provenance_result"
              grep -q '^baseline_event=crucible.campaign.fresh-lineage-baseline.v1$' "$campaign_provenance_result"
              grep -q '^refusal_reason=cross-provenance-corpus-reuse-refused$' "$campaign_provenance_result"

              determinism_guardrail_result="${determinismGuardrailGate}/result"
              grep -q '^PASS$' "$determinism_guardrail_result"
              grep -q '^tasks=T-DCE-7$' "$determinism_guardrail_result"
              grep -q '^harness_lint_extension=distribution-metadata-flow$' "$determinism_guardrail_result"
              grep -q '^distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban$' "$determinism_guardrail_result"

              fleet_equivalence_result="${fleetEquivalenceGate}/result"
              grep -q '^PASS$' "$fleet_equivalence_result"
              grep -q '^gate=gate:fleet-equivalence$' "$fleet_equivalence_result"
              grep -q '^tasks=T-DCE-8$' "$fleet_equivalence_result"
              grep -q '^finding_set=content-addressed$' "$fleet_equivalence_result"
              grep -q '^artifact_bytes=byte-identical$' "$fleet_equivalence_result"
              grep -q '^structural_equivalence=root-budget-graph-exhaustion$' "$fleet_equivalence_result"
              grep -q '^discovery_order=diagnostic-only$' "$fleet_equivalence_result"
              grep -q '^real_qemu_slice_source=checks.crucible.phase2.gates.singleVmFingerprint$' "$fleet_equivalence_result"
              grep -q '^divergence_bisection=SearchReplayOracleBisectionRequest$' "$fleet_equivalence_result"

              campaign_continuity_result="${campaignContinuityGate}/result"
              grep -q '^PASS$' "$campaign_continuity_result"
              grep -q '^gate=gate:campaign-continuity$' "$campaign_continuity_result"
              grep -q '^tasks=T-DCE-9$' "$campaign_continuity_result"
              grep -q '^seed_reproducibility=bit-identical-prior-corpus$' "$campaign_continuity_result"
              grep -q '^coverage_ratchet=monotone-non-decreasing$' "$campaign_continuity_result"
              grep -q '^accumulated_coverage=grow-only-union-crdt$' "$campaign_continuity_result"
              grep -q '^cross_provenance_reuse=refused$' "$campaign_continuity_result"
              grep -q '^fresh_lineage=forked$' "$campaign_continuity_result"
              grep -q '^provenance_seed_gate=triple-keyed$' "$campaign_continuity_result"
              grep -q '^prior_findings=reproducible$' "$campaign_continuity_result"

              test -x "${fleetStore}/bin/crucible-fleet-store"
              test -x "${explorer}/bin/crucible"
              probe_root="$TMPDIR/crucible-fleet-store"
              "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^backend=SharedDagStore$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^interface=DagStore::put,DagStore::get,DagStore::has$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^location_independent_roots=2$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^concurrent_put=idempotent$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^concurrent_writers=16$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^object_file_count=1$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^claim_lease=ttl-hint$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^claim_key=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^expired_lease=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^stale_claim_lock=reclaimable$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^reclaimed_node_byte_identical=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^hash_affinity=priority-only$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^affinity_filters_frontier=false$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^static_partitioning=false$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^exists_gated_expansion=skip-existing$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_map_admission=compare-and-merge$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_map_repair=entry-markers-before-fingerprint$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_map_duplicate=skipped$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^reduction_fingerprint=shared-prune$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^claim_set_anti_redundancy=unclaimed-first$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_store=persistent-dagstore$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_manifest=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_head=cas-advanced$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_head_lock=advisory-head-file$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_head_log=append-only-checksummed$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^manifest_head_only_mutable=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^manifest_root_objects=required$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^lost_cas=bookkeeping-only$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^read_merge_retry=enabled$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^merge_roots=materialized-objects$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_seed=prior-corpus$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_seed_artifact=self-contained$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_seed_replay=bit-identical$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_seed_process_state=not-required$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_ratchet=grow-only-union-crdt$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_ratchet_monotone=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_crdt=commutative-associative-idempotent$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^coverage_novelty=against-accumulated-map$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^findings_ledger=cross-run-grow-only$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^findings_ledger_dedup=content-addressed$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^finding_replay=bit-identical-from-ledger$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_gc_roots=manifest-roots$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_gc_scope=corpus,coverage,findings,genesis$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_gc_unpinned=swept-candidate$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_gc_value=cache-only$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^fat_to_thin_eviction=value-preserved$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^thin_checkpoint_source=parent-schedule-delta$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^corpus_retention=deterministic-seeded-cap$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^corpus_retention_authorized=explicit-policy$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^corpus_retention_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^corpus_retention_root=source-cap-seed-proof$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^findings_ledger_retention=never-evict$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity=implemented$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity_seed_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity_coverage_monotone=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity_cross_provenance_refused=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity_fresh_lineage=forked$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^campaign_continuity_prior_findings_reproducible=true$' "$TMPDIR/crucible-fleet-store.probe"
              grep -q '^provenance_seed_gate=triple-keyed$' "$TMPDIR/crucible-fleet-store.probe"

              mkdir -p "$out"
              cat > "$out/result" <<'RESULT'
              PASS
              check=checks.fleet.crucible-distributed-continuous-exploration
              gate=gate:fleet-equivalence
              source_check=checks.crucible.phase7.crucibleSharedDagStore
              package_check=checks.crucible.phase7.crucibleFleetStore
              e2e_gate_result=${e2eGate}/result
              fleet_store_gate_result=${fleetStoreGate}/result
              shared_dag_store_gate_result=${sharedDagStoreGate}/result
              frontier_lease_gate_result=${frontierLeaseGate}/result
              four_layer_dedup_gate_result=${fourLayerDedupGate}/result
              campaign_manifest_gate_result=${campaignManifestGate}/result
              campaign_seeding_gate_result=${campaignSeedingGate}/result
              campaign_storage_bounding_gate_result=${campaignStorageBoundingGate}/result
              campaign_provenance_gate_result=${campaignProvenanceGate}/result
              determinism_guardrail_gate_result=${determinismGuardrailGate}/result
              fleet_equivalence_gate_result=${fleetEquivalenceGate}/result
              campaign_continuity_gate_result=${campaignContinuityGate}/result
              fleet_store_component=${fleetStore}
              fleet_store_build_info=${fleetStore}/nix-support/crucible-fleet-store-build-info
              explorer_closure=${explorer}
              explorer_binary=${explorer}/bin/crucible
              fleet_surface=true
              vm_runner=tcg-only
              tcg_only=true
              required_system_features=none
              kvm_required=false
              shared_store_backend=SharedDagStore
              shared_store_interface=DagStore::put,DagStore::get,DagStore::has
              location_independent_roots=2
              concurrent_put=idempotent
              concurrent_writers=16
              object_file_count=1
              claim_lease=ttl-hint
              claim_key=content-addressed
              expired_lease=reclaimable
              stale_claim_lock=reclaimable
              reclaimed_node_byte_identical=true
              hash_affinity=priority-only
              affinity_filters_frontier=false
              static_partitioning=false
              dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set
              exists_gated_expansion=skip-existing
              coverage_map_admission=compare-and-merge
              coverage_map_repair=entry-markers-before-fingerprint
              coverage_map_duplicate=skipped
              reduction_fingerprint=shared-prune
              claim_set_anti_redundancy=unclaimed-first
              campaign_store=persistent-dagstore
              campaign_manifest=content-addressed
              campaign_head=cas-advanced
              campaign_head_lock=advisory-head-file
              campaign_head_log=append-only-checksummed
              manifest_head_only_mutable=true
              manifest_root_objects=required
              lost_cas=bookkeeping-only
              read_merge_retry=enabled
              merge_roots=materialized-objects
              campaign_seed=prior-corpus
              campaign_seed_artifact=self-contained
              campaign_seed_replay=bit-identical
              campaign_seed_process_state=not-required
              coverage_ratchet=grow-only-union-crdt
              coverage_ratchet_monotone=true
              coverage_crdt=commutative-associative-idempotent
              coverage_novelty=against-accumulated-map
              findings_ledger=cross-run-grow-only
              findings_ledger_dedup=content-addressed
              finding_replay=bit-identical-from-ledger
              campaign_gc_roots=manifest-roots
              campaign_gc_scope=corpus,coverage,findings,genesis
              campaign_gc_unpinned=swept-candidate
              campaign_gc_value=cache-only
              fat_to_thin_eviction=value-preserved
              thin_checkpoint_source=parent-schedule-delta
              corpus_retention=deterministic-seeded-cap
              corpus_retention_authorized=explicit-policy
              corpus_retention_reproducible=true
              corpus_retention_root=source-cap-seed-proof
              findings_ledger_retention=never-evict
              distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban
              distribution_metadata_lint=distribution-metadata-flow
              distribution_metadata_forbidden_paths=reduce,Decision,content-key,artifact
              distribution_metadata_allowed_paths=claim-lease,affinity,telemetry,progress
              fleet_equivalence_finding_set=content-addressed
              fleet_equivalence_artifacts=byte-identical
              fleet_equivalence_structural=root-budget-graph-exhaustion
              fleet_equivalence_order=diagnostic-only
              fleet_equivalence_real_qemu_slice=checks.crucible.phase2.gates.singleVmFingerprint
              fleet_equivalence_bisection=SearchReplayOracleBisectionRequest
              campaign_provenance_key=campaign_provenance_key
              campaign_gate=gate:campaign-continuity
              campaign_continuity_seed_reproducible=bit-identical-prior-corpus
              campaign_continuity_coverage_monotone=true
              campaign_continuity_cross_provenance_refused=true
              campaign_continuity_fresh_lineage=forked
              campaign_continuity_prior_findings_reproducible=true
              provenance_seed_gate=triple-keyed
              distributed_search_surface=enabled
              continuous_campaign_surface=enabled
              hermetic_inputs=fleet-store,explorer
              RESULT
            '';
          }
        ];
      };
  };

  crucibleReferenceIntegrity = import ./tests/crucible/reference-integrity.nix {
    inherit pkgs lib;
    crucibleChecks = crucibleChecksBase;
    fleetChecks = crucibleFleetChecks;
  };
  crucibleChecks =
    crucibleChecksBase
    // {
      referenceIntegrity = crucibleReferenceIntegrity;
    };
in {
  inherit lib pkgs stdenv modules mkSystem packagesWithExpose;

  # Auto-discovered golden image systems.
  # Each system has .config, .options, .build, and .checks.
  systems = discoverSystems;

  # Checks hierarchy — module checks come from systems, everything else
  # stays at the top level.
  checks = rec {
    eval-standalone = import ./lib/testing/eval.nix {
      inherit pkgs lib mkSystem packagesWithExpose;
      system = serverSystem;
    };
    # Pure evaluation and focused all-variant output contracts are one gate.
    # Rendered store paths remain contextual Nix references rather than
    # duplicated source snapshots.
    eval = pkgs.mkDerivation {
      pname = "aos-eval-and-system-structure-checks";
      version = "0";
      src = null;
      buildDeps = [
        eval-standalone
        system-structure
        config-eval
        config-manifest
        config-provenance
        config-materialize
        config-parity
        config-parity-p2
      ];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p $out
            echo PASS > $out/result
          '';
        }
      ];
    };
    build = let
      critical-pkgs = import ./tests/build/critical-pkgs.nix {inherit pkgs lib;};
      hardening-probe = import ./tests/build/hardening-probe.nix {inherit pkgs lib;};
      kernel-config = import ./tests/build/kernel-config.nix {inherit pkgs lib;};
      package-root-image = import ./lib/testing/package-root-image.nix {inherit pkgs lib;};
      systemd-verity = import ./lib/testing/systemd-verity.nix {inherit pkgs lib;};
      golden-image-budgets = lib.mapAttrs (_: system: system.checks.image-budget) discoverSystems;
    in {
      inherit critical-pkgs hardening-probe kernel-config package-root-image systemd-verity golden-image-budgets;
      # Single target that pulls in the whole build-check group.
      all = pkgs.mkDerivation {
        pname = "aos-build-checks-all";
        version = "0";
        src = null;
        buildDeps =
          [critical-pkgs kernel-config package-root-image systemd-verity]
          ++ builtins.attrValues hardening-probe
          ++ builtins.attrValues golden-image-budgets;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p $out
              echo "PASS" > $out/result
            '';
          }
        ];
      };
    };
    tla = import ./lib/testing/tla.nix {inherit pkgs lib;};
    trivial-builders = import ./lib/testing/trivial-builders.nix {inherit pkgs lib;};
    module-args = import ./lib/testing/module-args.nix {inherit pkgs lib;};
    module-enforcement = import ./lib/testing/module-enforcement.nix {inherit pkgs lib;};
    # Off-host config-eval preflight and flat-to-module parity gates.
    # (operability.md). Pure eval-time, next to checks.eval, cheap on every PR.
    config-eval = import ./lib/testing/config-eval.nix {inherit pkgs lib;};
    config-manifest = import ./lib/testing/config-manifest.nix {
      inherit pkgs lib;
      system = discoverSystems.server;
    };
    config-provenance = import ./lib/testing/config-provenance.nix {
      inherit pkgs mkSystem;
      serverModule = ./systems/server.nix;
    };
    config-source-gc = import ./lib/testing/config-source-gc.nix {inherit pkgs lib;};
    config-materialize = import ./lib/testing/config-materialize.nix {inherit pkgs lib;};
    config-parity = import ./lib/testing/config-parity.nix {inherit pkgs lib;};
    config-parity-p2 = import ./lib/testing/config-parity-p2.nix {inherit pkgs lib;};
    # Complete non-KVM on-host configuration gate. The image lifecycle and
    # degraded-network contracts are exercised by the fleet aggregate below.
    runtime-config-all = pkgs.mkDerivation {
      pname = "runtime-config-all";
      version = "0";
      src = null;
      buildDeps =
        [
          pkgs.aos
          pkgs.aos-evaluator-tests
          config-eval
          config-manifest
          config-materialize
          config-parity
          config-parity-p2
          eval
          module-args
          module-enforcement
          package-expose
          config-source-gc
          config-provenance
          system-structure
          systemd-credentials
          systemd-generate
          systemd-lib
          systemd-verity
        ]
        ++ builtins.attrValues lint;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p $out
            echo PASS > $out/result
          '';
        }
      ];
    };
    fleet-spec = import ./lib/testing/fleet-spec-check.nix {inherit pkgs lib;};
    systemd-lib = import ./lib/testing/systemd-lib.nix {inherit pkgs lib;};
    systemd-generate = import ./lib/testing/systemd-generate.nix {inherit pkgs lib;};
    crucible = crucibleChecks;
    system-structure = let
      variants = lib.mapAttrs (variant: system:
        import ./lib/testing/system-structure.nix {
          inherit pkgs lib variant system;
        })
      discoverSystems;
      check = pkgs.mkDerivation {
        pname = "aos-system-structure-all";
        version = "0";
        src = null;
        buildDeps = builtins.attrValues variants;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p $out
              echo PASS > $out/result
            '';
          }
        ];
      };
    in
      check
      // {
        inherit variants;
      };
    systemd-credentials = import ./lib/testing/systemd-credentials.nix {inherit pkgs lib;};
    systemd-verity = build.systemd-verity;
    package-expose = import ./lib/testing/package-expose.nix {
      inherit pkgs lib mkSystem packagesWithExpose;
    };
    package-firewall-reload = packageFirewallReloadCheck;
    package-expose-lifecycle = packageExposeLifecycleCheck;
    package-preset = packagePresetCheck;
    package-test-http-server = packageTestHttpServerCheck;
    selinux-base = selinuxBaseCheck;
    apm-install-at-boot = apmInstallAtBootCheck;
    lint = import ./lib/testing/package-lint.nix {inherit pkgs lib;};
    # Module-level VM checks (from server system, for backwards compat)
    vm =
      serverSystem.config.system.build.checks
      // {
        apm = apmTests;
        apm-install-at-boot = apmInstallAtBootCheck;
        package-expose-lifecycle = packageExposeLifecycleCheck;
        package-preset = packagePresetCheck;
        package-test-http-server = packageTestHttpServerCheck;
        selinux-base = selinuxBaseCheck;
      };
    integration = packageChecks // stdenvChecks;
    fleet = let
      base = discoverFleetTests // crucibleFleetChecks;
      runtimeConfigNames = [
        "apm-desired-sequencing"
        "apm-system-activation-fail"
        "apm-system-upgrade"
        "config-degraded-boot"
        "config-generation-gc-roots"
        "config-image-generation-axes"
        "config-secret-reference"
        "install-from-image"
        "measured-boot"
        "on-host-config-eval"
        "package-attestation-quote"
        "provisioning-boot"
        "runtime-config-role"
        "system-image-rollback"
      ];
      runtimeConfigFleet = builtins.map (name: base.${name}) runtimeConfigNames;
    in
      base
      // {
        runtime-config-all = pkgs.mkDerivation {
          pname = "runtime-config-fleet-all";
          version = "0";
          src = null;
          buildDeps = runtimeConfigFleet;
          phases = [
            {
              name = "check";
              script = ''
                mkdir -p $out
                echo PASS > $out/result
              '';
            }
          ];
        };
      };
  };
}
