##! Native ability recovery across package-process and hard power loss.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
  observerForwardSocket ? null,
  extraRuntimeModules ? [],
  extraHostModule ? "",
  additionalClosures ? [],
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
  postgresqlFixture = import ./_postgresql-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
  kubernetesFixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
  imageRolloutFixture = import ./_image-rollout-runtime-reference.nix {
    inherit lib pkgs;
  };
  authorityInterfaceRoots =
    map (entry: entry.package.abilities) fixture.orderedPackages
    ++ [
      postgresqlFixture.packageSet.suite.abilities
      kubernetesFixture.packageSet.kubernetes.abilities
      kubernetesFixture.packageSet.systemd.abilities
      imageRolloutFixture.package.abilities
    ];
  authorityMatrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  authorityMatrixSpec = pkgs.writeTextFile {
    name = "aos-authority-revocation-matrix-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON authorityMatrix.spec;
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
  observerRequires = lib.optional (observerForwardSocket != null) "aos-ability-crucible.service";
  observerAfter = ["local-fs.target"] ++ observerRequires;
  observerService = {
    description = "AOS native ability boundary test controller";
    wantedBy = ["multi-user.target"];
    requires = observerRequires;
    after = observerAfter;
    before = ["aos-activate.service"];
    serviceConfig =
      {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
      }
      // lib.optionalAttrs (observerForwardSocket != null) {
        Environment = "AOS_ABILITY_FORWARD_SOCKET=${observerForwardSocket}";
      };
  };
  observerModule = {
    environment.etc."aos/ability-execution-observer.json" = {
      text = observerConfiguration;
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = observerService;
  };
  observerSystem = mkSystem (fixture.runtimeModules ++ [observerModule] ++ extraRuntimeModules);
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
      requires = ${builtins.toJSON observerRequires};
      after = ${builtins.toJSON observerAfter};
      before = [ "aos-activate.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
        ${lib.optionalString (observerForwardSocket != null) ''
          Environment = "AOS_ABILITY_FORWARD_SOCKET=${observerForwardSocket}";
        ''}
      };
    };
    ${extraHostModule}
  '';
  packageRuntime =
    if qualificationImage
    then "runtime.guest_package_runtime()"
    else builtins.toJSON "${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped";
  qualificationImagePython =
    if qualificationImage
    then "True"
    else "False";
in {
  name = "ability-native-power-loss";
  timeout = 5400;
  bootTimeout = 600;

  machines.runtime = {
    system = observerSystem;
    extraModules = [bootInitrdIdentityModule];
    extraClosures =
      fixture.extraClosures
      ++ additionalClosures
      ++ authorityInterfaceRoots
      ++ [authorityMatrixSpec];
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
      PACKAGE_RUNTIME = ${packageRuntime}
      RUNTIME_AUDIT_MATRIX_SPEC = ${builtins.toJSON "${authorityMatrixSpec}/matrix-spec.json"}
      RUNTIME_AUDIT_INTERFACE_ROOTS = ${builtins.toJSON (map builtins.toString authorityInterfaceRoots)}
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      FLOCK = "${pkgs.util-linux}/bin/flock"
      PUBLISH_OPERATION = "publish-nginx-secondary-configuration"
      FIXTURE_ENVIRONMENT = {
          "authority": "reference",
          "key": "host",
          "stage": "host",
      }
      MANAGED_CONFIGURATION_INTERFACE = {
          "name": "aos.managed-configuration-effects",
          "abi": 1,
          "descriptor": "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab",
      }
      SYSTEMD_SERVICE_INTERFACE = {
          "name": "aos.systemd-service-effects",
          "abi": 1,
          "descriptor": "sha256:e02cd9535b3f97fbaf41066fd4b6ac8c2aa315f38188fb669815dccd291b4f98",
      }
      REFERENCE_ATTEMPT_TIMEOUT_MILLIS = 300_000
      REFERENCE_TOTAL_RECOVERY_MILLIS = 1_200_000
      OBSERVER_FORWARD_ENABLED = ${
        if observerForwardSocket == null
        then "False"
        else "True"
      }


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


      def retained_path_inventory(generations):
          inventory = {}
          for generation in generations:
              root = f"/var/lib/profiles/system/gen-{generation}"
              inventory[root] = runtime.succeed(
                  f"{FIND} {shlex.quote(root)} -xdev "
                  f"-printf '%y\\t%p\\t%l\\n' | {COREUTILS}/sort"
              )
          return inventory


      def collect_store_paths(value, paths):
          if isinstance(value, dict):
              for child in value.values():
                  collect_store_paths(child, paths)
          elif isinstance(value, list):
              for child in value:
                  collect_store_paths(child, paths)
          elif isinstance(value, str) and value.startswith("/nix/store/"):
              paths.add(value)


      def retained_store_paths(generations, transaction_root):
          paths = set()
          for generation in generations:
              collect_store_paths(read_json(
                  f"/var/lib/profiles/system/gen-{generation}/manifest.json"
              ), paths)
          collect_store_paths(read_json(
              f"{transaction_root}/plan-bundle.json"
          ), paths)
          assert paths, (generations, transaction_root)
          return sorted(paths)


      def assert_store_paths_exist(paths):
          for path in paths:
              runtime.succeed(f"test -e {shlex.quote(path)}")


      def disable_automatic_activation_recovery():
          drop_in_directory = "/run/systemd/system/aos-activate.service.d"
          drop_in = f"{drop_in_directory}/90-ability-unlocked-gc.conf"
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              {COREUTILS}/mkdir -p {drop_in_directory}
              {COREUTILS}/printf '%s\\n' '[Service]' 'Restart=no' > {drop_in}
              {SYSTEMCTL} daemon-reload
              test "$({SYSTEMCTL} show aos-activate.service -p Restart --value)" = no
          """))
          return drop_in


      def resume_activation_recovery(drop_in):
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              {COREUTILS}/rm -f {shlex.quote(drop_in)}
              {SYSTEMCTL} daemon-reload
              {SYSTEMCTL} reset-failed aos-activate.service
              {SYSTEMCTL} --no-block start aos-activate.service
          """))


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
          if ${qualificationImagePython}:
              assert runtime.boot == "published-image", runtime.boot
              return runtime.assert_published_boot_contract(expected_path)

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


      def arm_boundary(sequence, boundary="effect-returned", purpose="effect"):
          runtime.succeed(
              f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
              f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
          )
          write_canonical(TARGET, {
              "action": "disconnect",
              "boundary": boundary,
              "operation_key": PUBLISH_OPERATION,
              "purpose": purpose,
              "sequence": sequence,
          })


      def arm_pause(sequence, operation_key, boundary="effect-intent-durable"):
          runtime.succeed(
              f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
              f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
          )
          write_canonical(TARGET, {
              "action": "pause",
              "boundary": boundary,
              "operation_key": operation_key,
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


      def held_boundary(
          sequence,
          expected_boundary="effect-returned",
          expected_operation=PUBLISH_OPERATION,
          expected_purpose="effect",
      ):
          runtime.wait_until_succeeds(
              f"test -s {shlex.quote(HELD_EVENT)}", timeout=120
          )
          held = read_json(HELD_EVENT)
          event = held["event"]
          assert held["sequence"] == sequence, held
          assert event["boundary"] == expected_boundary, held
          assert event["purpose"] == expected_purpose, held
          assert event["operation"]["operation"]["key"] == expected_operation, held
          assert event["cancelled"] is False, held
          if OBSERVER_FORWARD_ENABLED:
              assert held["forwarded_acknowledgement"] == {
                  "action": "continue",
                  "event_digest": held["event_digest"],
                  "schema": "aos.ability-execution-boundary-ack/v1",
              }, held
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
          if OBSERVER_FORWARD_ENABLED:
              assert resumed["forwarded_acknowledgement"] == {
                  "action": "continue",
                  "event_digest": resumed["event_digest"],
                  "schema": "aos.ability-execution-boundary-ack/v1",
              }, resumed
          return resumed


      def transaction_at_boundary(held, completed=False):
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
          assert operation["interface"]["name"] == (
              "aos.managed-configuration-effects"
          ), operation
          assert operation["interface"]["abi"] == 1, operation
          assert operation["interface"]["descriptor"] == (
              "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab"
          ), operation
          assert operation["method"] == "publish", operation
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
          assert ("effect-completed" in kinds) == completed, (kinds, diagnostic)
          assert not any(kind.startswith("reconciled-") for kind in kinds), (
              kinds,
              diagnostic,
          )
          return (
              generation,
              transaction,
              plan,
              root,
              bundle_bytes,
              ordinal,
              {
                  "key": operation["key"],
                  "ordinal": ordinal,
                  "interface": operation["interface"],
                  "method": operation["method"],
                  "target": operation["target"],
              },
          )


      def required_success_dependent(bundle_bytes, publish_ordinal):
          bundle = json.loads(bundle_bytes)
          transition = bundle["transition"]
          effect = transition["effect_document"]
          operations = effect["operations"]
          assert bundle["schema"] == "aos.ability.plan-bundle/v1", bundle
          assert transition["schema"] in {
              "aos.ability.transition-snapshot/v1",
              "aos.ability.transition-snapshot/v2",
          }, transition
          assert publish_ordinal == 5, publish_ordinal
          publish = operations[publish_ordinal]

          def author(provider_key):
              provider = {
                  "environment": FIXTURE_ENVIRONMENT,
                  "key": provider_key,
              }
              matches = [
                  evaluation for evaluation in transition["evaluations"]
                  if evaluation["provider"] == provider
              ]
              assert len(matches) == 1, (provider, matches)
              descriptor = matches[0]["implementation"]["descriptor"]
              assert descriptor.startswith("sha256:"), descriptor
              descriptor_hex = descriptor.removeprefix("sha256:")
              assert len(descriptor_hex) == 64 and all(
                  character in "0123456789abcdef"
                  for character in descriptor_hex
              ), descriptor
              assert matches[0]["result"]["status"] == "returned", matches[0]
              return {
                  "provider": provider,
                  "implementation-descriptor": descriptor,
              }

          publish_author = author("shared-configuration")
          dependent_author = author("nginx-secondary")
          expected_publish = {
              "key": {
                  "scope": [
                      "shared-configuration",
                      publish_author["implementation-descriptor"].removeprefix(
                          "sha256:"
                      ),
                  ],
                  "key": "publish-nginx-secondary-configuration",
              },
              "ordinal": 5,
              "interface": MANAGED_CONFIGURATION_INTERFACE,
              "method": "publish",
              "target": {
                  "interface": MANAGED_CONFIGURATION_INTERFACE,
                  "resource": {
                      "provider": {
                          "environment": FIXTURE_ENVIRONMENT,
                          "key": "shared-configuration",
                      },
                      "key": "nginx-secondary-configuration",
                  },
                  "operations": ["publish"],
                  "lifetime": "instance",
              },
          }
          assert {
              "key": publish["key"],
              "ordinal": publish_ordinal,
              "interface": publish["interface"],
              "method": publish["method"],
              "target": publish["target"],
          } == expected_publish, publish

          publish_node = {"kind": "operation", "key": publish["key"]}
          outgoing = [
              edge for edge in effect["edges"]
              if edge["from"] == publish_node
              and edge["kind"] == "required-success"
          ]
          assert len(outgoing) == 1, (publish, outgoing)
          edge = outgoing[0]
          assert edge["to"]["kind"] == "operation", edge

          matching = [
              (ordinal, operation)
              for ordinal, operation in enumerate(operations)
              if operation["key"] == edge["to"]["key"]
          ]
          assert len(matching) == 1, (edge, matching)
          ordinal, operation = matching[0]
          expected_dependent = {
              "key": {
                  "scope": [
                      "nginx-secondary",
                      dependent_author["implementation-descriptor"].removeprefix(
                          "sha256:"
                      ),
                  ],
                  "key": "reload-nginx-secondary-service",
              },
              "ordinal": 2,
              "interface": SYSTEMD_SERVICE_INTERFACE,
              "method": "reload",
              "target": {
                  "interface": SYSTEMD_SERVICE_INTERFACE,
                  "resource": {
                      "provider": {
                          "environment": FIXTURE_ENVIRONMENT,
                          "key": "shared-service",
                      },
                      "key": "nginx-secondary-service",
                  },
                  "operations": ["reload"],
                  "lifetime": "instance",
              },
          }
          actual_dependent = {
              "key": operation["key"],
              "ordinal": ordinal,
              "interface": operation["interface"],
              "method": operation["method"],
              "target": operation["target"],
          }
          assert actual_dependent == expected_dependent, operation
          return (
              ordinal,
              actual_dependent,
              edge,
              {
                  "schema": "aos.qualification.host-resource-cohort-subject/v1",
                  "plan": bundle["plan"],
                  "plan-bundle-digest": (
                      "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()
                  ),
                  "authoring-evaluations": {
                      "publish": publish_author,
                      "dependent": dependent_author,
                  },
                  "publish-operation": expected_publish,
                  "dependent-operation": expected_dependent,
              },
          )


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


      def boundary_events(transaction, plan, operation_key=PUBLISH_OPERATION):
          events = [
              (position, json.loads(line))
              for position, line in enumerate(runtime.succeed(
                  f"{COREUTILS}/cat {shlex.quote(EVENTS)}"
              ).splitlines())
              if line
          ]

          def matches_operation(event):
              observed = event["operation"]["operation"]
              if isinstance(operation_key, dict):
                  return observed == operation_key
              return observed["key"] == operation_key

          return [
              {**event, "transcript-position": position}
              for position, event in events
              if event["transaction"] == transaction
              and event["operation"]["plan"] == plan
              and matches_operation(event)
          ]


      def timeline_events(diagnostic, ordinal):
          return [
              {
                  "sequence": event["sequence"],
                  "kind": event["kind"],
                  "node-ordinal": event["node_ordinal"],
              }
              for event in diagnostic["timeline"]["events"]
              if event.get("node_ordinal") == ordinal
          ]


      def boundary_timeline(events):
          return [
              {
                  "transcript-position": event["transcript-position"],
                  "purpose": event["purpose"],
                  "boundary": event["boundary"],
              }
              for event in events
          ]


      def assert_recovered(
          generation,
          transaction,
          plan,
          root,
          bundle_bytes,
          ordinal,
          operation_identity,
          sequence,
          expected_kinds=None,
          expected_boundaries=None,
          continuation_required=True,
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
          target_events = timeline_events(diagnostic, ordinal)
          kinds = [event["kind"] for event in target_events]
          if expected_kinds is None:
              expected_kinds = [
                  "operation-admitted",
                  "effect-started",
                  "operation-admitted",
                  "reconciliation-started",
                  "reconciled-completed",
              ]
          assert kinds == expected_kinds, (kinds, diagnostic)
          sequences = [event["sequence"] for event in target_events]
          assert sequences == sorted(set(sequences)), target_events
          assert operation_identity["method"] == "publish", operation_identity

          observed = boundary_events(transaction, plan)
          observed_boundaries = [
              (event["purpose"], event["boundary"])
              for event in observed
          ]
          if expected_boundaries is None:
              expected_boundaries = [
                  ("effect", "effect-intent-durable"),
                  ("effect", "effect-returned"),
                  ("reconcile", "reconciliation-intent-durable"),
                  ("reconcile", "reconciliation-returned"),
                  ("reconcile", "reconciliation-outcome-durable"),
              ]
          assert observed_boundaries == expected_boundaries, observed
          positions = [event["transcript-position"] for event in observed]
          assert positions == sorted(set(positions)), observed
          if continuation_required:
              assert read_json(CONTINUE) == {"sequence": sequence}


      print("waiting for the observer-enabled reference VM")
      if ${qualificationImagePython}:
          expected_boot_initrd = runtime.published_boot_identity()
      else:
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
      baseline_generation = current_generation()
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      foreign_mapping_before, foreign_content_before = (
          assert_managed_configuration_selected(
              activation_v1, "nginx-primary"
          )
      )
      secondary_mapping_before, secondary_content_before = (
          assert_managed_configuration_selected(
              activation_v1, "nginx-secondary"
          )
      )

      # Pause a real Publish after its durable intent and fresh acquisition,
      # then replace its ownership marker with an independently injected
      # foreign resource identity. The adapter must reject before mutation,
      # and the checked reload successor must remain absent because its
      # prerequisite failed.
      print("rejecting a foreign managed resource and blocking its dependent")
      activation_negative = generate_activation_fixture(
          f"{BOUNDARY_ROOT}/activation-negative",
          "alpha-v1",
          "gamma-negative",
          f"{BOUNDARY_ROOT}/authority-negative",
      )
      provision_operator_authority(
          activation_negative, f"{BOUNDARY_ROOT}/authority-negative"
      )
      host_negative = f"{BOUNDARY_ROOT}/host-negative.nix"
      write_activation_host(host_negative, activation_negative, OBSERVER_HOST_MODULE)
      persist_fixture_file(host_negative)
      secondary_service_pid_before = runtime.succeed(
          f"{SYSTEMCTL} show nginx-nginx-secondary.service "
          "-p MainPID --value"
      ).strip()
      assert secondary_service_pid_before not in {"", "0"}
      arm_pause("foreign-resource", PUBLISH_OPERATION)
      start_switch("ability-boundary-negative.service", host_negative, "negative")

      held_negative = held_boundary(
          "foreign-resource", "effect-intent-durable"
      )
      negative_state = transaction_at_boundary(held_negative)
      negative_dependency = required_success_dependent(
          negative_state[4], negative_state[5]
      )
      secondary_destination = secondary_mapping_before["qualification"][
          "destination"
      ]
      secondary_marker_path = (
          "/var/lib/aos/ability-runtime/managed-configuration/revisions/"
          "sha256:" + hashlib.sha256(secondary_destination.encode()).hexdigest()
      )
      secondary_marker_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(secondary_marker_path)}"
      )
      injected_foreign_marker = json.loads(secondary_marker_before)
      injected_foreign_marker["resource"]["key"] = (
          "foreign-secondary-configuration"
      )
      encoded_foreign_marker = base64.b64encode(
          json.dumps(
              injected_foreign_marker,
              ensure_ascii=False,
              separators=(",", ":"),
              sort_keys=True,
          ).encode()
      ).decode()
      runtime.succeed(
          f"{COREUTILS}/printf '%s' {shlex.quote(encoded_foreign_marker)} "
          f"| {COREUTILS}/base64 -d > {shlex.quote(secondary_marker_path)}"
      )
      foreign_target_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(secondary_destination)}"
      )
      foreign_ownership_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(secondary_marker_path)}"
      )
      assert json.loads(foreign_ownership_before) == injected_foreign_marker
      foreign_resource_snapshot_before = json.dumps(
          {
              "content": foreign_target_before,
              "ownership": foreign_ownership_before,
          },
          ensure_ascii=False,
          separators=(",", ":"),
          sort_keys=True,
      )
      foreign_primary_before = runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(foreign_mapping_before['qualification']['destination'])}"
      )

      release_reconciliation("foreign-resource")
      wait_switch("ability-boundary-negative.service", False)
      foreign_target_after = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(secondary_destination)}"
      )
      foreign_ownership_after = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(secondary_marker_path)}"
      )
      foreign_resource_snapshot_after = json.dumps(
          {
              "content": foreign_target_after,
              "ownership": foreign_ownership_after,
          },
          ensure_ascii=False,
          separators=(",", ":"),
          sort_keys=True,
      )
      foreign_primary_after = runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(foreign_mapping_before['qualification']['destination'])}"
      )
      assert foreign_target_after == foreign_target_before
      assert foreign_ownership_after == foreign_ownership_before
      assert foreign_primary_after == foreign_primary_before
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      negative_route_after = route_body("gamma.example", 18082)
      secondary_service_pid_after = runtime.succeed(
          f"{SYSTEMCTL} show nginx-nginx-secondary.service "
          "-p MainPID --value"
      ).strip()
      assert secondary_service_pid_after == secondary_service_pid_before

      negative_diagnostic = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{negative_state[0]} "
          f"{shlex.quote(negative_state[1])}"
      ))
      negative_publish_timeline = timeline_events(
          negative_diagnostic, negative_state[5]
      )
      negative_dependent_timeline = timeline_events(
          negative_diagnostic, negative_dependency[0]
      )
      assert [event["kind"] for event in negative_publish_timeline] == [
          "operation-admitted",
          "effect-started",
          "rejected-before-effect",
      ], negative_diagnostic
      assert negative_dependent_timeline == [], negative_diagnostic
      negative_publish_boundaries = boundary_events(
          negative_state[1], negative_state[2]
      )
      assert [
          (event["purpose"], event["boundary"])
          for event in negative_publish_boundaries
      ] == [
          ("effect", "effect-intent-durable"),
          ("effect", "effect-returned"),
          ("effect", "effect-outcome-durable"),
      ], negative_publish_boundaries
      negative_failure_record = runtime.succeed(
          f"{COREUTILS}/sha256sum "
          f"{shlex.quote(negative_state[3] + '/execution.journal')}"
      ).split()[0]

      # Restore the independently corrupted marker before returning to the
      # completed baseline. The unchanged marker must authenticate exactly one
      # owner again, while the failed generation remains available as evidence.
      encoded_secondary_marker = base64.b64encode(
          secondary_marker_before.encode()
      ).decode()
      runtime.succeed(
          f"{COREUTILS}/printf '%s' {shlex.quote(encoded_secondary_marker)} "
          f"| {COREUTILS}/base64 -d > {shlex.quote(secondary_marker_path)}; "
          f"{COREUTILS}/rm -f {shlex.quote(TARGET)} {shlex.quote(HELD_EVENT)} "
          f"{shlex.quote(CONTINUE)}"
      )
      secondary_mapping_restored, secondary_content_restored = (
          assert_managed_configuration_selected(
              activation_v1, "nginx-secondary"
          )
      )
      assert secondary_mapping_restored == secondary_mapping_before
      assert secondary_content_restored == secondary_content_before
      runtime.succeed(
          f"{APM} rollback --system --generation {baseline_generation}",
          timeout=600,
      )
      assert current_generation() == baseline_generation
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
      process_dependency = required_success_dependent(
          process_state[4], process_state[5]
      )
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
      dependent_route_while_unsettled = route_body("gamma.example", 18082)
      foreign_mapping_unsettled, foreign_content_unsettled = (
          assert_managed_configuration_selected(
              activation_process, "nginx-primary"
          )
      )
      assert foreign_mapping_unsettled == foreign_mapping_before
      assert foreign_content_unsettled == foreign_content_before
      recovery_drop_in = disable_automatic_activation_recovery()
      kill_exact_activation_runtime()
      wait_switch("ability-boundary-process.service", False)

      print("collecting while the crashed activation is unlocked and unresolved")
      runtime.wait_until_succeeds(
          f"{SYSTEMCTL} is-failed --quiet aos-activate.service", timeout=120
      )
      assert runtime.succeed(
          f"{SYSTEMCTL} show aos-activate.service -p Restart --value"
      ).strip() == "no"
      assert runtime.succeed(
          f"{SYSTEMCTL} show aos-activate.service -p InvocationID --value"
      ).strip() == process_invocation_before
      runtime.succeed(
          f"{FLOCK} --exclusive --nonblock /run/apm/switch.lock "
          f"{COREUTILS}/true"
      )

      recovery_generations = [baseline_generation, process_state[0]]
      assert len(set(recovery_generations)) == 2, recovery_generations
      recovery_inventory_before = retained_path_inventory(recovery_generations)
      recovery_store_paths = retained_store_paths(
          recovery_generations, process_state[3]
      )
      assert_store_paths_exist(recovery_store_paths)
      execution_journal_before_gc = runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(process_state[3] + '/execution.journal')}"
      ).encode()

      clean_unresolved = json.loads(runtime.succeed(
          f"{APM} --json clean --system --generations --keep 1",
          timeout=600,
      ))
      retained_unresolved = clean_unresolved["configuration"][
          "generations_after"
      ]
      assert baseline_generation in retained_unresolved, clean_unresolved
      assert process_state[0] in retained_unresolved, clean_unresolved
      runtime.succeed(f"{APM} gc", timeout=600)

      assert retained_path_inventory(recovery_generations) == (
          recovery_inventory_before
      )
      assert_store_paths_exist(recovery_store_paths)
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(process_state[3] + '/plan-bundle.json')}"
      ).encode() == process_state[4]
      assert runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(process_state[3] + '/execution.journal')}"
      ).encode() == execution_journal_before_gc
      selected_after_gc, selected_content_after_gc = (
          assert_managed_configuration_selected(
              activation_process, "nginx-secondary"
          )
      )
      assert selected_after_gc == selected_process, (
          selected_process,
          selected_after_gc,
      )
      assert selected_content_after_gc == selected_process_content
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      foreign_mapping_after_gc, foreign_content_after_gc = (
          assert_managed_configuration_selected(
              activation_process, "nginx-primary"
          )
      )
      assert foreign_mapping_after_gc == foreign_mapping_before
      assert foreign_content_after_gc == foreign_content_before
      assert runtime.succeed(
          f"{SYSTEMCTL} show aos-activate.service -p InvocationID --value"
      ).strip() == process_invocation_before
      runtime.succeed(
          f"{FLOCK} --exclusive --nonblock /run/apm/switch.lock "
          f"{COREUTILS}/true"
      )

      print("resuming the same interrupted activation after collection")
      resume_activation_recovery(recovery_drop_in)
      process_reconciliation_returned = resumed_boundary(
          "process-loss", process_state[1], process_state[2]
      )
      process_diagnostic_before_completion = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{process_state[0]} "
          f"{shlex.quote(process_state[1])}"
      ))
      dependent_timeline_before_completion = timeline_events(
          process_diagnostic_before_completion, process_dependency[0]
      )
      dependent_boundaries_before_completion = boundary_events(
          process_state[1], process_state[2], process_dependency[1]["key"]
      )
      assert dependent_timeline_before_completion == [], (
          dependent_timeline_before_completion,
          process_diagnostic_before_completion,
      )
      assert dependent_boundaries_before_completion == [], (
          dependent_boundaries_before_completion
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
      dependent_route_after_recovery = route_body("gamma.example", 18082)
      foreign_mapping_after_recovery, foreign_content_after_recovery = (
          assert_managed_configuration_selected(
              activation_process, "nginx-primary"
          )
      )
      assert foreign_mapping_after_recovery == foreign_mapping_before
      assert foreign_content_after_recovery == foreign_content_before
      process_diagnostic = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{process_state[0]} "
          f"{shlex.quote(process_state[1])}"
      ))
      process_timeline = timeline_events(process_diagnostic, process_state[5])
      dependent_timeline_after_recovery = timeline_events(
          process_diagnostic, process_dependency[0]
      )
      process_boundary_events = boundary_events(
          process_state[1], process_state[2]
      )
      dependent_boundary_events_after_recovery = boundary_events(
          process_state[1], process_state[2], process_dependency[1]["key"]
      )
      publish_reconciled = [
          event for event in process_timeline
          if event["kind"] == "reconciled-completed"
      ]
      assert len(publish_reconciled) == 1, process_timeline
      assert {
          key: value
          for key, value in process_boundary_events[3].items()
          if key != "transcript-position"
      } == process_reconciliation_returned["event"], (
          process_boundary_events[3],
          process_reconciliation_returned,
      )
      assert [event["kind"] for event in dependent_timeline_after_recovery] == [
          "operation-admitted",
          "effect-started",
          "effect-completed",
      ], dependent_timeline_after_recovery
      dependent_sequences = [
          event["sequence"] for event in dependent_timeline_after_recovery
      ]
      assert dependent_sequences == sorted(set(dependent_sequences)), (
          dependent_timeline_after_recovery
      )
      assert publish_reconciled[0]["sequence"] < dependent_sequences[0], (
          publish_reconciled,
          dependent_timeline_after_recovery,
      )
      assert [
          (event["purpose"], event["boundary"])
          for event in dependent_boundary_events_after_recovery
      ] == [
          ("effect", "effect-intent-durable"),
          ("effect", "effect-returned"),
          ("effect", "effect-outcome-durable"),
      ], dependent_boundary_events_after_recovery
      dependent_boundary_positions = [
          event["transcript-position"]
          for event in dependent_boundary_events_after_recovery
      ]
      assert dependent_boundary_positions == sorted(
          set(dependent_boundary_positions)
      ), dependent_boundary_events_after_recovery
      assert (
          process_boundary_events[3]["transcript-position"]
          < dependent_boundary_positions[0]
      ), (process_boundary_events, dependent_boundary_events_after_recovery)
      process_authority = current_authority(process_state[1], process_state[2])

      crash_cases = [
          {
              "scenario": "interrupt-after-durable-intent",
              "boundary": "effect-intent-durable",
              "response": "gamma-intent",
              "completed_at_boundary": False,
              "reconciliation_expected": True,
              "expected_kinds": [
                  "operation-admitted",
                  "effect-started",
                  "operation-admitted",
                  "reconciliation-started",
                  "reconciled-safe-to-retry",
                  "operation-admitted",
                  "effect-started",
                  "effect-completed",
              ],
              "expected_boundaries": [
                  ("effect", "effect-intent-durable"),
                  ("reconcile", "reconciliation-intent-durable"),
                  ("reconcile", "reconciliation-returned"),
                  ("reconcile", "reconciliation-outcome-durable"),
                  ("effect", "effect-intent-durable"),
                  ("effect", "effect-returned"),
                  ("effect", "effect-outcome-durable"),
              ],
          },
          {
              "scenario": "interrupt-after-durable-outcome",
              "boundary": "effect-outcome-durable",
              "response": "gamma-outcome",
              "completed_at_boundary": True,
              "reconciliation_expected": False,
              "expected_kinds": [
                  "operation-admitted",
                  "effect-started",
                  "effect-completed",
              ],
              "expected_boundaries": [
                  ("effect", "effect-intent-durable"),
                  ("effect", "effect-returned"),
                  ("effect", "effect-outcome-durable"),
              ],
          },
      ]
      crash_results = {}
      for case in crash_cases:
          scenario = case["scenario"]
          print(f"interrupting the package runtime for {scenario}")
          activation = generate_activation_fixture(
              f"{BOUNDARY_ROOT}/activation-{scenario}",
              "alpha-v1",
              case["response"],
              f"{BOUNDARY_ROOT}/authority-{scenario}",
          )
          provision_operator_authority(
              activation, f"{BOUNDARY_ROOT}/authority-{scenario}"
          )
          host = f"{BOUNDARY_ROOT}/host-{scenario}.nix"
          write_activation_host(host, activation, OBSERVER_HOST_MODULE)
          persist_fixture_file(host)
          prior_generation = current_generation()
          prior_route = route_body("gamma.example", 18082)
          foreign_before, foreign_content_before_case = (
              assert_managed_configuration_selected(activation, "nginx-primary")
          )
          recovery_drop_in = disable_automatic_activation_recovery()
          arm_boundary(scenario, case["boundary"])
          start_switch(f"ability-boundary-{scenario}.service", host, scenario)

          held = held_boundary(scenario, case["boundary"])
          state = transaction_at_boundary(
              held, completed=case["completed_at_boundary"]
          )
          dependency = required_success_dependent(state[4], state[5])
          journal_before_loss = runtime.succeed(
              f"{COREUTILS}/sha256sum "
              f"{shlex.quote(state[3] + '/execution.journal')}"
          ).split()[0]
          diagnostic_before = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"/var/lib/profiles/system/gen-{state[0]} "
              f"{shlex.quote(state[1])}"
          ))
          dependent_before = timeline_events(diagnostic_before, dependency[0])
          dependent_boundaries_before = boundary_events(
              state[1], state[2], dependency[1]["key"]
          )
          assert dependent_before == [], (scenario, dependent_before)
          assert dependent_boundaries_before == [], (
              scenario,
              dependent_boundaries_before,
          )
          route_before_recovery = route_body("gamma.example", 18082)
          assert route_before_recovery == prior_route, (
              scenario,
              prior_route,
              route_before_recovery,
          )
          selected_unsettled = None
          if case["completed_at_boundary"]:
              selected_unsettled, selected_content_unsettled = (
                  assert_managed_configuration_selected(
                      activation, "nginx-secondary"
                  )
              )
              assert case["response"] in selected_content_unsettled, (
                  scenario,
                  selected_unsettled,
              )
          foreign_unsettled, foreign_content_unsettled_case = (
              assert_managed_configuration_selected(activation, "nginx-primary")
          )
          assert foreign_unsettled == foreign_before
          assert foreign_content_unsettled_case == foreign_content_before_case

          kill_exact_activation_runtime()
          wait_switch(f"ability-boundary-{scenario}.service", False)
          runtime.wait_until_succeeds(
              f"{SYSTEMCTL} is-failed --quiet aos-activate.service", timeout=120
          )

          generations = [prior_generation, state[0]]
          assert len(set(generations)) == 2, (scenario, generations)
          inventory_before_gc = retained_path_inventory(generations)
          store_paths = retained_store_paths(generations, state[3])
          assert_store_paths_exist(store_paths)
          clean_unresolved = json.loads(runtime.succeed(
              f"{APM} --json clean --system --generations --keep 1",
              timeout=600,
          ))
          retained_unresolved = clean_unresolved["configuration"][
              "generations_after"
          ]
          assert prior_generation in retained_unresolved, clean_unresolved
          assert state[0] in retained_unresolved, clean_unresolved
          runtime.succeed(f"{APM} gc", timeout=600)
          assert retained_path_inventory(generations) == inventory_before_gc
          assert_store_paths_exist(store_paths)
          if selected_unsettled is not None:
              selected_after_unsettled_gc, selected_content_after_unsettled_gc = (
                  assert_managed_configuration_selected(
                      activation, "nginx-secondary"
                  )
              )
              assert selected_after_unsettled_gc == selected_unsettled
              assert selected_content_after_unsettled_gc == selected_content_unsettled
          foreign_after_gc, foreign_content_after_gc_case = (
              assert_managed_configuration_selected(activation, "nginx-primary")
          )
          assert foreign_after_gc == foreign_before
          assert foreign_content_after_gc_case == foreign_content_before_case

          resume_activation_recovery(recovery_drop_in)
          if case["reconciliation_expected"]:
              resumed_boundary(scenario, state[1], state[2])
              release_reconciliation(scenario)
          runtime.wait_until_succeeds(
              f"{SYSTEMCTL} is-active --quiet aos-activate.service", timeout=600
          )
          runtime.wait_until_succeeds(
              "systemctl is-active --quiet nginx-nginx-secondary.service",
              timeout=300,
          )
          assert_recovered(
              *state,
              scenario,
              expected_kinds=case["expected_kinds"],
              expected_boundaries=case["expected_boundaries"],
              continuation_required=case["reconciliation_expected"],
          )
          route_after_recovery = route_body("gamma.example", 18082)
          assert case["response"] in route_after_recovery, (
              scenario,
              route_after_recovery,
          )
          selected_after_recovery, selected_content_after_recovery = (
              assert_managed_configuration_selected(
                  activation, "nginx-secondary"
              )
          )
          foreign_after, foreign_content_after_case = (
              assert_managed_configuration_selected(activation, "nginx-primary")
          )
          assert foreign_after == foreign_before
          assert foreign_content_after_case == foreign_content_before_case
          runtime.succeed(f"{APM} gc", timeout=600)
          selected_after_gc, selected_content_after_gc_case = (
              assert_managed_configuration_selected(
                  activation, "nginx-secondary"
              )
          )
          assert selected_after_gc == selected_after_recovery
          assert selected_content_after_gc_case == selected_content_after_recovery

          diagnostic_after = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"/var/lib/profiles/system/gen-{state[0]} "
              f"{shlex.quote(state[1])}"
          ))
          publish_timeline = timeline_events(diagnostic_after, state[5])
          publish_boundaries = boundary_events(state[1], state[2])
          dependent_after = timeline_events(diagnostic_after, dependency[0])
          dependent_boundaries_after = boundary_events(
              state[1], state[2], dependency[1]["key"]
          )
          assert [event["kind"] for event in dependent_after] == [
              "operation-admitted",
              "effect-started",
              "effect-completed",
          ], (scenario, dependent_after)
          assert [
              (event["purpose"], event["boundary"])
              for event in dependent_boundaries_after
          ] == [
              ("effect", "effect-intent-durable"),
              ("effect", "effect-returned"),
              ("effect", "effect-outcome-durable"),
          ], (scenario, dependent_boundaries_after)
          assert publish_timeline[-1]["sequence"] < dependent_after[0]["sequence"]
          assert (
              publish_boundaries[-1]["transcript-position"]
              < dependent_boundaries_after[0]["transcript-position"]
          )
          crash_results[scenario] = {
              "state": state,
              "dependency": dependency,
              "journal-before-loss": journal_before_loss,
              "publish-timeline": publish_timeline,
              "publish-boundaries": publish_boundaries,
              "dependent-before": dependent_before,
              "dependent-boundaries-before": dependent_boundaries_before,
              "dependent-after": dependent_after,
              "dependent-boundaries-after": dependent_boundaries_after,
              "route-before-recovery": route_before_recovery,
              "route-after-recovery": route_after_recovery,
              "selected-after-gc": selected_after_gc,
              "foreign-before": foreign_before,
              "foreign-content-before": foreign_content_before_case,
              "foreign-content-unsettled": foreign_content_unsettled_case,
              "foreign-content-after-gc": foreign_content_after_gc_case,
              "foreign-content-after-recovery": foreign_content_after_case,
          }


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
      assert_route(
          "gamma.example",
          18082,
          "app-c",
          crash_cases[-1]["response"],
      )
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

      crash_results["lose-external-result"] = {
          "state": process_state,
          "dependency": process_dependency,
          "journal-before-loss": pending_journal_before_maintenance.split()[0],
          "publish-timeline": process_timeline,
          "publish-boundaries": process_boundary_events,
          "dependent-before": dependent_timeline_before_completion,
          "dependent-boundaries-before": dependent_boundaries_before_completion,
          "dependent-after": dependent_timeline_after_recovery,
          "dependent-boundaries-after": dependent_boundary_events_after_recovery,
          "route-before-recovery": dependent_route_while_unsettled,
          "route-after-recovery": dependent_route_after_recovery,
          "selected-after-gc": selected_after_gc,
          "foreign-before": foreign_mapping_before,
          "foreign-content-before": foreign_content_before,
          "foreign-content-unsettled": foreign_content_unsettled,
          "foreign-content-after-gc": foreign_content_after_gc,
          "foreign-content-after-recovery": foreign_content_after_recovery,
      }

      crash_dispositions = {
          "interrupt-after-durable-intent": "reconciled-after-interruption",
          "lose-external-result": "reconciled-completed",
          "interrupt-after-durable-outcome": "completed-before-interruption",
      }
      interruption_indexes = {
          "interrupt-after-durable-intent": 0,
          "lose-external-result": 1,
          "interrupt-after-durable-outcome": 2,
      }


      def crash_probes(scenario, result):
          state = result["state"]
          dependency = result["dependency"]
          publish_timeline = result["publish-timeline"]
          publish_boundaries = result["publish-boundaries"]
          dependent_after = result["dependent-after"]
          dependent_boundaries_after = result["dependent-boundaries-after"]
          disposition = crash_dispositions[scenario]
          selected = result["selected-after-gc"]
          foreign = result["foreign-before"]

          return {
              "durable-attempt-state-classified": {
                  "kind": "journal-timeline",
                  "disposition": disposition,
                  "detail": (
                      "The native journal retained the exact interrupted Publish "
                      "boundary and recovered it without exposing its successor early."
                  ),
                  "observations": {
                      "transaction": state[1],
                      "plan": state[2],
                      "operation": state[6],
                      "journal-before-loss": result["journal-before-loss"],
                      "timeline": publish_timeline,
                      "boundary-timeline": boundary_timeline(publish_boundaries),
                      "interruption-position": publish_boundaries[
                          interruption_indexes[scenario]
                      ]["transcript-position"],
                      "settlement-position": publish_boundaries[-1][
                          "transcript-position"
                      ],
                  },
              },
              "at-most-one-resource-owner": {
                  "kind": "ownership-inventory",
                  "disposition": disposition,
                  "detail": (
                      "The managed-configuration catalog selected one exact "
                      "resource marker before and after collection."
                  ),
                  "observations": {
                      "resource": selected["resource"],
                      "destination": selected["qualification"]["destination"],
                      "revision": selected["revision"],
                      "matching-markers": 1,
                      "selected-after-gc": True,
                  },
              },
              "foreign-resources-unchanged": {
                  "kind": "foreign-resource-snapshot",
                  "disposition": disposition,
                  "detail": (
                      "The independently selected primary configuration retained "
                      "the same mapping and bytes through loss, GC, and recovery."
                  ),
                  "observations": {
                      "resource": foreign["resource"],
                      "revision": foreign["revision"],
                      "content-before": result["foreign-content-before"],
                      "content-unsettled": result["foreign-content-unsettled"],
                      "content-after-gc": result["foreign-content-after-gc"],
                      "content-after-recovery": result[
                          "foreign-content-after-recovery"
                      ],
                  },
              },
              "dependent-effects-not-executed": {
                  "kind": "dependency-barrier",
                  "disposition": disposition,
                  "detail": (
                      "The checked reload successor had no journal or boundary "
                      "event before Publish recovery settled, then ran "
                      "once and changed the consumer route."
                  ),
                  "observations": {
                      "publish-operation": state[6],
                      "dependent-operation": dependency[1],
                      "dependency-edge": dependency[2],
                      "timeline-before-completion": result["dependent-before"],
                      "effect-boundaries-before-completion": boundary_timeline(
                          result["dependent-boundaries-before"]
                      ),
                      "publish-settlement-sequence": publish_timeline[-1]["sequence"],
                      "publish-settlement-position": (
                          publish_boundaries[-1]["transcript-position"]
                      ),
                      "timeline-after-recovery": dependent_after,
                      "effect-boundary-timeline": boundary_timeline(
                          dependent_boundaries_after
                      ),
                      "dependent-effect-return-position": (
                          dependent_boundaries_after[1]["transcript-position"]
                      ),
                      "route-while-unsettled": result["route-before-recovery"],
                      "route-after-recovery": result["route-after-recovery"],
                      "changed-only-after-recovery": (
                          result["route-before-recovery"]
                          != result["route-after-recovery"]
                      ),
                  },
              },
          }


      matrix_cell_prefix = (
          "managed-configuration/aos.managed-configuration-effects/abi-1/"
          "publish/"
      )
      foreign_resource_cell = matrix_cell_prefix + "reject-foreign-resource-mutation"
      blocked_dependent_cell = (
          "systemd-service-legacy/aos.systemd-service-effects/abi-1/"
          "reload/block-dependent-effect"
      )
      NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS = {
          matrix_cell_prefix + scenario: result["dependency"][3]
          for scenario, result in crash_results.items()
      }
      NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS.update({
          foreign_resource_cell: negative_dependency[3],
          blocked_dependent_cell: negative_dependency[3],
      })
      NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLES = {
          matrix_cell_prefix + scenario: result["state"][4]
          for scenario, result in crash_results.items()
      }
      NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLES.update({
          foreign_resource_cell: negative_state[4],
          blocked_dependent_cell: negative_state[4],
      })
      NATIVE_ADAPTER_MATRIX_PROBES = {
          matrix_cell_prefix + scenario: crash_probes(scenario, result)
          for scenario, result in crash_results.items()
      }
      NATIVE_ADAPTER_MATRIX_PROBES.update({
          foreign_resource_cell: {
              "durable-attempt-state-classified": {
                  "kind": "journal-timeline",
                  "disposition": "foreign-mutation-rejected",
                  "detail": (
                      "The production journal durably classified Publish as a "
                      "settled rejection after the owned bytes became foreign."
                  ),
                  "observations": {
                      "transaction": negative_state[1],
                      "plan": negative_state[2],
                      "operation": negative_state[6],
                      "timeline": negative_publish_timeline,
                      "cause-operation": negative_state[6],
                      "cause-timeline": negative_publish_timeline,
                      "boundary-timeline": boundary_timeline(
                          negative_publish_boundaries
                      ),
                      "failure-record": negative_failure_record,
                      "classified": True,
                  },
              },
              "at-most-one-resource-owner": {
                  "kind": "ownership-inventory",
                  "disposition": "foreign-mutation-rejected",
                  "detail": (
                      "The foreign target retained its one ownership marker "
                      "throughout the rejected effect."
                  ),
                  "observations": {
                      "resource": negative_state[6]["target"]["resource"],
                      "owner-count-before": 1,
                      "owner-count-after": 1,
                      "one-owner-throughout": True,
                      "owner-evidence-before": foreign_ownership_before,
                      "owner-evidence-after": foreign_ownership_after,
                  },
              },
              "foreign-resources-unchanged": {
                  "kind": "foreign-resource-snapshot",
                  "disposition": "foreign-mutation-rejected",
                  "detail": (
                      "The foreign marker and target content retained exact bytes "
                      "throughout the rejected publication."
                  ),
                  "observations": {
                      "resource": injected_foreign_marker["resource"],
                      "snapshot-before": foreign_resource_snapshot_before,
                      "snapshot-after": foreign_resource_snapshot_after,
                      "unchanged": (
                          foreign_resource_snapshot_before
                          == foreign_resource_snapshot_after
                      ),
                  },
              },
              "dependent-effects-not-executed": {
                  "kind": "dependency-barrier",
                  "disposition": "foreign-mutation-rejected",
                  "detail": (
                      "The checked reload successor retained no journal or effect "
                      "boundary after the foreign Publish rejection."
                  ),
                  "observations": {
                      "predecessor-operation": negative_state[6],
                      "dependent-operation": negative_dependency[1],
                      "dependency-edge": negative_dependency[2],
                      "dependent-timeline": negative_dependent_timeline,
                      "dependent-effect-boundaries": [],
                      "behavior-before": "app-c:gamma-v1\n",
                      "behavior-after": negative_route_after,
                      "blocked": True,
                  },
              },
              "foreign-attempt-rejected-before-mutation": {
                  "kind": "foreign-attempt-rejection",
                  "disposition": "foreign-mutation-rejected",
                  "detail": (
                      "Publish observed foreign bytes after admission and left "
                      "those bytes unchanged when it rejected the effect."
                  ),
                  "observations": {
                      "foreign-resource": injected_foreign_marker["resource"],
                      "attempted-resource": injected_foreign_marker["resource"],
                      "authorized-resources": [
                          negative_state[6]["target"]["resource"]
                      ],
                      "rejection": "foreign-authority-rejected",
                      "mutation-count": 0,
                      "rejected-before-mutation": True,
                  },
              },
          },
          blocked_dependent_cell: {
              "durable-attempt-state-classified": {
                  "kind": "journal-timeline",
                  "disposition": "dependent-effect-blocked",
                  "detail": (
                      "The production journal retained the failed Publish and no "
                      "admission for its required-success reload successor."
                  ),
                  "observations": {
                      "transaction": negative_state[1],
                      "plan": negative_state[2],
                      "operation": negative_dependency[1],
                      "timeline": negative_dependent_timeline,
                      "cause-operation": negative_state[6],
                      "cause-timeline": negative_publish_timeline,
                      "boundary-timeline": boundary_timeline(
                          negative_publish_boundaries
                      ),
                      "failure-record": negative_failure_record,
                      "classified": True,
                  },
              },
              "at-most-one-resource-owner": {
                  "kind": "ownership-inventory",
                  "disposition": "dependent-effect-blocked",
                  "detail": (
                      "The blocked service resource retained one live baseline owner."
                  ),
                  "observations": {
                      "resource": negative_dependency[1]["target"]["resource"],
                      "owner-count-before": 1,
                      "owner-count-after": 1,
                      "one-owner-throughout": True,
                      "owner-evidence-before": secondary_service_pid_before,
                      "owner-evidence-after": secondary_service_pid_after,
                  },
              },
              "foreign-resources-unchanged": {
                  "kind": "foreign-resource-snapshot",
                  "disposition": "dependent-effect-blocked",
                  "detail": (
                      "The independent primary configuration retained exact bytes "
                      "while the secondary reload remained blocked."
                  ),
                  "observations": {
                      "resource": foreign_mapping_before["resource"],
                      "snapshot-before": foreign_primary_before,
                      "snapshot-after": foreign_primary_after,
                      "unchanged": foreign_primary_before == foreign_primary_after,
                      "cell": blocked_dependent_cell,
                  },
              },
              "dependent-effects-not-executed": {
                  "kind": "dependency-barrier",
                  "disposition": "dependent-effect-blocked",
                  "detail": (
                      "The required-success reload had no journal or boundary "
                      "events and the live route retained the predecessor result."
                  ),
                  "observations": {
                      "predecessor-operation": negative_state[6],
                      "dependent-operation": negative_dependency[1],
                      "dependency-edge": negative_dependency[2],
                      "dependent-timeline": negative_dependent_timeline,
                      "dependent-effect-boundaries": [],
                      "behavior-before": "app-c:gamma-v1\n",
                      "behavior-after": negative_route_after,
                      "blocked": True,
                      "cell": blocked_dependent_cell,
                  },
              },
              "prerequisite-failure-recorded": {
                  "kind": "prerequisite-failure",
                  "disposition": "dependent-effect-blocked",
                  "detail": (
                      "The predecessor failure remains in the durable execution "
                      "journal and the dependent effect count is zero."
                  ),
                  "observations": {
                      "predecessor-operation": negative_state[6],
                      "dependent-operation": negative_dependency[1],
                      "dependency-edge": negative_dependency[2],
                      "failure-record": f"sha256:{negative_failure_record}",
                      "dependent-effect-count": 0,
                  },
              },
          },
      })
      runtime_audit_output = "/var/lib/aos/qualification-native-adapter-runtime.json"
      runtime_audit_arguments = " ".join(
          shlex.quote(value)
          for value in [
              RUNTIME_AUDIT_MATRIX_SPEC,
              runtime_audit_output,
              *RUNTIME_AUDIT_INTERFACE_ROOTS,
          ]
      )
      runtime.succeed(
          f"{Path(PACKAGE_RUNTIME).parent}/aos-ability-authority-audit "
          f"{runtime_audit_arguments}",
          timeout=1800,
      )
      NATIVE_ADAPTER_MATRIX_RUNTIME_AUDIT = json.loads(
          runtime.succeed(f"{COREUTILS}/cat {shlex.quote(runtime_audit_output)}")
      )
    '';
  }
  // lib.optionalAttrs qualificationImage {
    qualification = {
      candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
      extraClosures =
        fixture.extraClosures
        ++ additionalClosures
        ++ authorityInterfaceRoots
        ++ [authorityMatrixSpec observerController];
      setupBody = fixture.qualificationSetupBody + observerHostModule;
    };
  }
