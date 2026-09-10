##! Native ability recovery across package-process and hard power loss.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
  };

  observerController = pkgs.writeTextFile {
    name = "aos-ability-boundary-controller";
    destination = "/bin/aos-ability-boundary-controller";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      ${builtins.readFile ./ability-boundary-observer.py}
    '';
  };
  observerConfiguration = ''{"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}'';
  observerService = {
    description = "AOS native ability boundary test controller";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    before = ["aos-activate.service"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
      Restart = "on-failure";
      RestartSec = "1s";
      RuntimeDirectory = "aos-instrumentation";
      RuntimeDirectoryMode = "0700";
      UMask = "0077";
    };
  };
  observerModule = {
    environment.etc."aos/ability-execution-observer.json" = {
      text = observerConfiguration;
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = observerService;
  };
  observerSystem = mkSystem (fixture.runtimeModules ++ [observerModule]);
  bootInitrdIdentityModule = {config, ...}: {
    # The fleet harness applies this module to the effective machine system,
    # so it records the same initrd output that the harness passes to QEMU.
    environment.etc."aos/fleet-boot-initrd".text = ''
      ${config.system.build.initrd}/initrd.img
    '';
  };

  # Every switched generation must retain the opt-in and controller because
  # native execution begins only after that generation replaces /etc.
  observerHostModule = ''
    environment.etc."aos/ability-execution-observer.json" = {
      text = ${builtins.toJSON observerConfiguration};
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = {
      description = "AOS native ability boundary test controller";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      before = [ "aos-activate.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
      };
    };
  '';
in {
  name = "ability-native-power-loss";
  timeout = 5400;
  bootTimeout = 600;

  machines.runtime = {
    system = observerSystem;
    extraModules = [bootInitrdIdentityModule];
    extraClosures = fixture.extraClosures;
    varSizeMiB = 8192;
    memoryMiB = 4096;
  };

  testScript =
    fixture.testPrelude
    + # python
    ''
      from pathlib import Path


      BOUNDARY_ROOT = "/var/lib/aos/ability-boundary-test"
      CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
      EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
      HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
      RESUMED_EVENT = f"{BOUNDARY_ROOT}/resumed-event.json"
      TARGET = f"{BOUNDARY_ROOT}/target.json"
      OBSERVER_HOST_MODULE = ${builtins.toJSON observerHostModule}
      OBSERVER_CONTROLLER = (
          "${observerController}/bin/aos-ability-boundary-controller"
      )
      PACKAGE_RUNTIME = (
          "${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped"
      )
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      PUBLISH_OPERATION = "publish-nginx-secondary-configuration"
      REFERENCE_ATTEMPT_TIMEOUT_MILLIS = 300_000
      REFERENCE_TOTAL_RECOVERY_MILLIS = 1_200_000


      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def write_canonical(path, value):
          payload = json.dumps(
              value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
          ).encode()
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} "
              f"{payload.hex()}"
          )


      def persist_fixture_file(path):
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(path)}"
          )


      def read_json(path):
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(path)}"
          ))


      def retained_host_handoff(generation):
          generation_root = f"/var/lib/profiles/system/gen-{generation}"
          contract_path = (
              f"{generation_root}/toplevel/initrd/initrd-stage-contract.json"
          )
          contract_bytes = runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(contract_path)}"
          ).encode()
          contract = json.loads(contract_bytes)
          handoff = contract["handoff"]

          assert contract["schema_version"] == (
              "aos.boot.initrd-stage-contract/v1"
          ), contract
          assert contract["stage"] == "initrd", contract
          assert handoff["to_stage"] == "host", handoff
          assert handoff["mechanism"] == "systemd-switch-root", handoff
          assert handoff["transferable_handles"] is False, handoff
          assert handoff["receiving_stage_reauthorizes"] is True, handoff
          assert handoff["receiving_stage_reacquires"] is True, handoff
          assert {
              "initrd_path": "/sysroot/var/lib/profiles/system",
              "host_path": "/var/lib/profiles/system",
          } in handoff["durable_state_roots"], handoff

          return contract_bytes


      def actual_boot_initrd_identity(expected_path):
          assert runtime.boot == "kernel", runtime.boot
          assert runtime.initrd_path == expected_path, (
              runtime.initrd_path,
              expected_path,
          )

          initrd_path = Path(runtime.initrd_path)
          contract_path = initrd_path.parent / "initrd-stage-contract.json"
          contract_bytes = contract_path.read_bytes()
          contract = json.loads(contract_bytes)
          artifact = contract["artifact"]

          digest = hashlib.sha256()
          with initrd_path.open("rb") as initrd_file:
              for chunk in iter(lambda: initrd_file.read(1024 * 1024), b""):
                  digest.update(chunk)

          assert artifact == {
              "path": "initrd.img",
              "sha256": f"sha256:{digest.hexdigest()}",
              "size_bytes": initrd_path.stat().st_size,
          }, (artifact, initrd_path)
          assert contract["schema_version"] == (
              "aos.boot.initrd-stage-contract/v1"
          ), contract
          assert contract["stage"] == "initrd", contract

          handoff = contract["handoff"]
          assert handoff["to_stage"] == "host", handoff
          assert handoff["mechanism"] == "systemd-switch-root", handoff
          assert handoff["transferable_handles"] is False, handoff
          assert handoff["receiving_stage_reauthorizes"] is True, handoff
          assert handoff["receiving_stage_reacquires"] is True, handoff
          assert {
              "initrd_path": "/sysroot/var/lib/profiles/system",
              "host_path": "/var/lib/profiles/system",
          } in handoff["durable_state_roots"], handoff

          return runtime.initrd_path, contract_bytes


      def current_authority(transaction, plan):
          assert plan.startswith("sha256:"), plan
          authority = (
              f"/run/apm/ability-authority/{plan.removeprefix('sha256:')}/"
              f"{transaction}.json"
          )
          runtime.wait_until_succeeds(
              f"test -s {shlex.quote(authority)}", timeout=120
          )
          return read_json(authority)


      def assert_fresh_receiving_authority(before, after, plan):
          preserved_fields = [
              "schema",
              "policy_fence",
              "policy_revision",
              "resolution_policy",
              "platform_policy",
              "transition_authority",
              "plan",
              "bindings",
          ]
          for field in preserved_fields:
              assert after[field] == before[field], (field, before, after)
          assert after["plan"] == plan, after

          def assignment_key(assignment):
              return json.dumps(
                  {
                      "provider": assignment["provider"],
                      "interface": assignment["interface"],
                      "implementation": assignment["implementation"],
                  },
                  separators=(",", ":"),
                  sort_keys=True,
              )

          before_assignments = {
              assignment_key(assignment): assignment
              for assignment in before["provider_assignments"]
          }
          after_assignments = {
              assignment_key(assignment): assignment
              for assignment in after["provider_assignments"]
          }
          assert after_assignments, after
          assert after_assignments.keys() <= before_assignments.keys(), (
              before_assignments,
              after_assignments,
          )

          def observed_resources(authority):
              return {
                  json.dumps(
                      observation["resource"],
                      separators=(",", ":"),
                      sort_keys=True,
                  )
                  for observation in authority["resource_observations"]
              }

          assert observed_resources(after), after
          assert observed_resources(after) <= observed_resources(before), (
              before["resource_observations"],
              after["resource_observations"],
          )
          assert after != before, (before, after)


      def systemd_assignments(authority):
          return {
              json.dumps(
                  {
                      "provider": assignment["provider"],
                      "interface": assignment["interface"],
                      "implementation": assignment["implementation"],
                  },
                  separators=(",", ":"),
                  sort_keys=True,
              ): assignment
              for assignment in authority["provider_assignments"]
              if assignment["interface"]["name"]
              == "aos.systemd-service-effects"
          }


      def assert_reacquired_systemd(before, after):
          before_assignments = systemd_assignments(before)
          after_assignments = systemd_assignments(after)
          assert before_assignments, before
          assert after_assignments.keys() == before_assignments.keys(), (
              before_assignments,
              after_assignments,
          )
          for key, assignment in before_assignments.items():
              assert (
                  after_assignments[key]["incarnation"]
                  != assignment["incarnation"]
              ), (assignment, after_assignments[key])


      def arm_boundary(sequence):
          runtime.succeed(
              f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
              f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
          )
          write_canonical(TARGET, {
              "boundary": "effect-returned",
              "operation_key": PUBLISH_OPERATION,
              "purpose": "effect",
              "sequence": sequence,
          })


      def release_reconciliation(sequence):
          write_canonical(CONTINUE, {"sequence": sequence})


      def start_switch(unit, host, label):
          runtime.succeed(
              f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
              f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} "
              "--property=Type=exec "
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/ability-eval-{shlex.quote(label)}"
          )


      def wait_switch(unit, success):
          expected = "0" if success else None
          runtime.wait_until_succeeds(
              f"state=$({SYSTEMCTL} show -p ActiveState --value "
              f"{shlex.quote(unit)}); test \"$state\" = inactive -o \"$state\" = failed",
              timeout=600,
          )
          status = runtime.succeed(
              f"{SYSTEMCTL} show -p ExecMainStatus --value {shlex.quote(unit)}"
          ).strip()
          if expected is None:
              assert status != "0", (unit, status, runtime.succeed(
                  f"journalctl -u {shlex.quote(unit)} --no-pager 2>&1 || true"
              ))
          else:
              assert status == expected, (unit, status, runtime.succeed(
                  f"journalctl -u {shlex.quote(unit)} --no-pager 2>&1 || true"
              ))


      def start_maintenance(unit, command):
          runtime.succeed(
              f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
              f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} "
              f"--property=Type=exec {command}"
          )


      def assert_maintenance_rejected_by_switch_lock(unit):
          runtime.wait_until_succeeds(
              f"state=$({SYSTEMCTL} show -p ActiveState --value "
              f"{shlex.quote(unit)}); test \"$state\" = failed",
              timeout=120,
          )
          status = runtime.succeed(
              f"{SYSTEMCTL} show -p ExecMainStatus --value {shlex.quote(unit)}"
          ).strip()
          journal = runtime.succeed(
              f"journalctl -u {shlex.quote(unit)} --no-pager 2>&1 || true"
          )
          assert status != "0", (unit, status, journal)
          assert "/run/apm/switch.lock" in journal, (unit, journal)
          assert "another system switch is active" in journal, (unit, journal)


      def held_boundary(sequence):
          runtime.wait_until_succeeds(
              f"test -s {shlex.quote(HELD_EVENT)}", timeout=120
          )
          held = read_json(HELD_EVENT)
          event = held["event"]
          assert held["sequence"] == sequence, held
          assert event["boundary"] == "effect-returned", held
          assert event["purpose"] == "effect", held
          assert event["operation"]["operation"]["key"] == PUBLISH_OPERATION, held
          assert event["cancelled"] is False, held
          return held


      def resumed_boundary(sequence, transaction, plan):
          runtime.wait_until_succeeds(
              f"test -s {shlex.quote(RESUMED_EVENT)}", timeout=300
          )
          resumed = read_json(RESUMED_EVENT)
          event = resumed["event"]
          assert resumed["sequence"] == sequence, resumed
          assert event["boundary"] == "reconciliation-returned", resumed
          assert event["purpose"] == "reconcile", resumed
          assert event["transaction"] == transaction, resumed
          assert event["operation"]["plan"] == plan, resumed
          assert event["operation"]["operation"]["key"] == PUBLISH_OPERATION, resumed
          return resumed


      def transaction_at_boundary(held):
          generation = current_generation()
          transaction = held["event"]["transaction"]
          plan = held["event"]["operation"]["plan"]
          root = (
              f"/var/lib/profiles/system/gen-{generation}/ability-transactions/"
              f"{transaction}"
          )
          bundle_bytes = runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(root + '/plan-bundle.json')}"
          ).encode()
          bundle = json.loads(bundle_bytes)
          assert bundle["plan"] == plan, (bundle, held)
          matching = [
              (ordinal, operation)
              for ordinal, operation in enumerate(
                  bundle["transition"]["effect_document"]["operations"]
              )
              if operation["key"]["key"] == PUBLISH_OPERATION
          ]
          assert len(matching) == 1, matching
          ordinal, operation = matching[0]
          assert operation["deadline"] == {
              "attempt_timeout_millis": REFERENCE_ATTEMPT_TIMEOUT_MILLIS,
              "total_recovery_millis": REFERENCE_TOTAL_RECOVERY_MILLIS,
          }, operation

          diagnostic = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"/var/lib/profiles/system/gen-{generation} "
              f"{shlex.quote(transaction)}"
          ))
          target_events = [
              event for event in diagnostic["timeline"]["events"]
              if event.get("node_ordinal") == ordinal
          ]
          kinds = [event["kind"] for event in target_events]
          assert "effect-started" in kinds, (kinds, diagnostic)
          assert "effect-completed" not in kinds, (kinds, diagnostic)
          assert not any(kind.startswith("reconciled-") for kind in kinds), (
              kinds,
              diagnostic,
          )
          return generation, transaction, plan, root, bundle_bytes, ordinal


      def kill_exact_activation_runtime():
          killed = runtime.succeed(textwrap.dedent(f"""
              set -eu
              matches=""
              for executable in /proc/[0-9]*/exe; do
                target=$({COREUTILS}/readlink "$executable" 2>/dev/null || true)
                [ "$target" = {shlex.quote(PACKAGE_RUNTIME)} ] || continue
                process=''${{executable#/proc/}}
                process=''${{process%/exe}}
                command=$({COREUTILS}/tr '\\000' ' ' \
                  < "/proc/$process/cmdline" 2>/dev/null || true)
                case " $command " in
                  *" __activate-config "*) matches="$matches $process" ;;
                esac
              done
              set -- $matches
              [ "$#" -eq 1 ]
              kill -KILL "$1"
              printf '%s\\n' "$1"
          """))
          assert killed.strip().isdigit(), killed


      def boundary_events(transaction, plan):
          events = [
              json.loads(line)
              for line in runtime.succeed(
                  f"{COREUTILS}/cat {shlex.quote(EVENTS)}"
              ).splitlines()
              if line
          ]
          return [
              event for event in events
              if event["transaction"] == transaction
              and event["operation"]["plan"] == plan
              and event["operation"]["operation"]["key"] == PUBLISH_OPERATION
          ]


      def assert_recovered(
          generation, transaction, plan, root, bundle_bytes, ordinal, sequence
      ):
          record = read_json(
              f"/var/lib/profiles/system/gen-{generation}/activation.json"
          )
          assert record["status"] == "complete", record
          assert record["native_ability_transaction"] == transaction, record
          assert runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(root + '/plan-bundle.json')}"
          ).encode() == bundle_bytes

          diagnostic = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"/var/lib/profiles/system/gen-{generation} "
              f"{shlex.quote(transaction)}"
          ))
          target_events = [
              event for event in diagnostic["timeline"]["events"]
              if event.get("node_ordinal") == ordinal
          ]
          kinds = [event["kind"] for event in target_events]
          assert kinds.count("effect-started") == 1, (kinds, diagnostic)
          assert kinds.count("effect-completed") == 0, (kinds, diagnostic)
          assert kinds.count("operation-admitted") >= 2, (kinds, diagnostic)
          assert kinds.count("reconciliation-started") == 1, (kinds, diagnostic)
          assert kinds.count("reconciled-completed") == 1, (kinds, diagnostic)

          observed = boundary_events(transaction, plan)
          effect_returns = [
              event for event in observed
              if event["purpose"] == "effect"
              and event["boundary"] == "effect-returned"
          ]
          reconciliation_returns = [
              event for event in observed
              if event["purpose"] == "reconcile"
              and event["boundary"] == "reconciliation-returned"
          ]
          assert len(effect_returns) == 1, observed
          assert len(reconciliation_returns) == 1, observed
          assert read_json(CONTINUE) == {"sequence": sequence}


      print("waiting for the observer-enabled reference VM")
      expected_boot_initrd = runtime.succeed(
          f"{COREUTILS}/cat /etc/aos/fleet-boot-initrd"
      ).strip()
      boot_initrd_identity_before = actual_boot_initrd_identity(
          expected_boot_initrd
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_for_unit("aos-ability-boundary-controller.service", timeout=120)
      runtime.succeed("test -S /run/aos-instrumentation/controller.sock")

      print("publishing authenticated reference ability packages")
      publish_reference_packages()

      # Establish a completed generation whose live service remains unchanged
      # while the next generation publishes its configuration candidate.
      print("establishing the completed baseline generation")
      activation_v1 = generate_activation_fixture(
          f"{BOUNDARY_ROOT}/activation-v1",
          "alpha-v1",
          "gamma-v1",
          f"{BOUNDARY_ROOT}/authority-v1",
      )
      authority_v1 = provision_operator_authority(
          activation_v1, f"{BOUNDARY_ROOT}/authority-v1"
      )
      runtime.succeed(f"test -f {shlex.quote(authority_v1)}")
      host_v1 = f"{BOUNDARY_ROOT}/host-v1.nix"
      write_activation_host(host_v1, activation_v1, OBSERVER_HOST_MODULE)
      persist_fixture_file(host_v1)
      runtime.succeed(
          f"{APM} switch --from {shlex.quote(host_v1)} "
          "--eval-root /run/ability-eval-v1",
          timeout=600,
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=120
      )
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")

      # Kill the exact native executor after Publish returned success but
      # before the journal can record its outcome. A second invocation of the
      # same persistent host input must reopen and reconcile the same plan.
      print("interrupting the package runtime after Publish returned")
      activation_process = generate_activation_fixture(
          f"{BOUNDARY_ROOT}/activation-process",
          "alpha-v1",
          "gamma-process",
          f"{BOUNDARY_ROOT}/authority-process",
      )
      provision_operator_authority(
          activation_process, f"{BOUNDARY_ROOT}/authority-process"
      )
      host_process = f"{BOUNDARY_ROOT}/host-process.nix"
      write_activation_host(host_process, activation_process, OBSERVER_HOST_MODULE)
      persist_fixture_file(host_process)
      arm_boundary("process-loss")
      start_switch("ability-boundary-process.service", host_process, "process")

      held_process = held_boundary("process-loss")
      process_state = transaction_at_boundary(held_process)
      pending_state_before_maintenance = runtime.succeed(
          f"{COREUTILS}/cat /var/lib/profiles/system/state.json"
      )
      pending_journal_before_maintenance = runtime.succeed(
          f"{COREUTILS}/sha256sum "
          f"{shlex.quote(process_state[3] + '/execution.journal')}"
      )

      print("rejecting generation pruning and GC during the partial transition")
      start_maintenance(
          "ability-boundary-clean.service",
          f"{APM} clean --system --generations --keep 1",
      )
      start_maintenance("ability-boundary-gc.service", f"{APM} gc")
      assert_maintenance_rejected_by_switch_lock(
          "ability-boundary-clean.service"
      )
      assert_maintenance_rejected_by_switch_lock(
          "ability-boundary-gc.service"
      )
      assert runtime.succeed(
          f"{COREUTILS}/cat /var/lib/profiles/system/state.json"
      ) == pending_state_before_maintenance
      assert runtime.succeed(
          f"{COREUTILS}/sha256sum "
          f"{shlex.quote(process_state[3] + '/execution.journal')}"
      ) == pending_journal_before_maintenance
      runtime.succeed(
          f"test -s {shlex.quote(process_state[3] + '/plan-bundle.json')}"
      )
      process_invocation_before = runtime.succeed(
          f"{SYSTEMCTL} show aos-activate.service -p InvocationID --value"
      ).strip()
      assert process_invocation_before, process_invocation_before
      selected_process, selected_process_content = assert_managed_configuration_selected(
          activation_process, "nginx-secondary"
      )
      assert "gamma-process" in selected_process_content, selected_process
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      kill_exact_activation_runtime()
      wait_switch("ability-boundary-process.service", False)

      print("waiting for systemd to restart the interrupted activation")
      resumed_boundary(
          "process-loss", process_state[1], process_state[2]
      )
      release_reconciliation("process-loss")
      runtime.wait_until_succeeds(
          f"{SYSTEMCTL} is-active --quiet aos-activate.service", timeout=600
      )
      process_invocation_after = runtime.succeed(
          f"{SYSTEMCTL} show aos-activate.service -p InvocationID --value"
      ).strip()
      assert (
          process_invocation_after
          and process_invocation_after != process_invocation_before
      ), (process_invocation_before, process_invocation_after)
      assert_recovered(*process_state, "process-loss")
      assert_route("gamma.example", 18082, "app-c", "gamma-process")
      process_authority = current_authority(process_state[1], process_state[2])

      # Repeat the same real boundary, then remove power from the whole guest.
      # The relaunch keeps the writable disk and metadata channel, while the
      # next boot supplies a fresh systemd manager and admission decision.
      print("interrupting the VM after Publish returned")
      activation_power = generate_activation_fixture(
          f"{BOUNDARY_ROOT}/activation-power",
          "alpha-v1",
          "gamma-power",
          f"{BOUNDARY_ROOT}/authority-power",
      )
      provision_operator_authority(
          activation_power, f"{BOUNDARY_ROOT}/authority-power"
      )
      host_power = f"{BOUNDARY_ROOT}/host-power.nix"
      write_activation_host(host_power, activation_power, OBSERVER_HOST_MODULE)
      persist_fixture_file(host_power)
      arm_boundary("power-loss")
      start_switch("ability-boundary-power.service", host_power, "power")

      held_power = held_boundary("power-loss")
      power_state = transaction_at_boundary(held_power)
      handoff_contract_before = retained_host_handoff(power_state[0])
      authority_before = current_authority(power_state[1], power_state[2])
      selected_power, selected_power_content = assert_managed_configuration_selected(
          activation_power, "nginx-secondary"
      )
      assert "gamma-power" in selected_power_content, selected_power
      assert_route("gamma.example", 18082, "app-c", "gamma-process")
      boot_id_before = runtime.succeed(
          f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
      ).strip()
      manager_id_before = runtime.succeed(
          f"{SYSTEMCTL} show init.scope -p InvocationID --value"
      ).strip()
      assert manager_id_before, manager_id_before

      print("cutting VM power and booting from the unchanged writable disk")
      runtime.power_cycle(timeout=600)
      assert (
          actual_boot_initrd_identity(expected_boot_initrd)
          == boot_initrd_identity_before
      )

      boot_id_after = runtime.succeed(
          f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
      ).strip()
      manager_id_after = runtime.succeed(
          f"{SYSTEMCTL} show init.scope -p InvocationID --value"
      ).strip()
      assert boot_id_after != boot_id_before, (boot_id_before, boot_id_after)
      assert manager_id_after and manager_id_after != manager_id_before, (
          manager_id_before,
          manager_id_after,
      )
      assert retained_host_handoff(power_state[0]) == handoff_contract_before
      print("releasing boot-time reconciliation after power loss")
      resumed_boundary("power-loss", power_state[1], power_state[2])
      authority_after = current_authority(power_state[1], power_state[2])
      assert_fresh_receiving_authority(
          authority_before, authority_after, power_state[2]
      )
      release_reconciliation("power-loss")
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-activate.service", timeout=600
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=300
      )
      assert current_generation() == power_state[0], (
          current_generation(),
          power_state,
      )
      assert_recovered(*power_state, "power-loss")
      power_authority = current_authority(power_state[1], power_state[2])
      assert_reacquired_systemd(process_authority, power_authority)
      assert_route("gamma.example", 18082, "app-c", "gamma-power")

      print("pruning and collecting after the recovered transaction settles")
      clean = json.loads(runtime.succeed(
          f"{APM} --json clean --system --generations --keep 1",
          timeout=600,
      ))
      assert power_state[0] in clean["configuration"]["generations_after"], clean
      runtime.succeed(f"{APM} gc", timeout=600)
      assert current_generation() == power_state[0]
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state[3] + '/plan-bundle.json')}"
      ).encode() == power_state[4]
      assert_route("gamma.example", 18082, "app-c", "gamma-power")
    '';
}
