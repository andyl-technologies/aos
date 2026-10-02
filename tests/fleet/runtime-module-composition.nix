##! Exercises ordinary native package modules, reload, and durable recovery.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
  forwardObserverToCrucible ? false,
  extraRuntimeModules ? [],
  extraHostModule ? "",
  additionalClosures ? [],
  ...
}: let
  observer = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
    forwardToCrucible = forwardObserverToCrucible;
  };
  extraSource = builtins.toFile "runtime-module-extra-policy.nix" ''
    { lib, ... }: {
      ${extraHostModule}
    }
  '';
  selectedFixture = import ./_native-fixture-selection.nix {inherit lib;} {
    inherit runtimeSystem;
    scenarioSources = [observer.source] ++ lib.optional (extraHostModule != "") extraSource;
  };
  runtimeSystem = mkSystem ([
      ../../systems/server-test.nix
      {
        aos.packages = {
          nginx = {
            package = pkgs.nginx;
            bundle = true;
          };
          envoy = {
            package = pkgs.envoy;
            bundle = true;
          };
          k3s-worker = {
            package = pkgs.k3s-worker;
            bundle = true;
          };
          aos-ability-boundary-observer = {
            package = observer.package;
            bundle = true;
          };
        };
      }
    ]
    ++ extraRuntimeModules
    ++ [
      {
        aos.activation.stages.host.configuration = selectedFixture.sources;
      }
    ]);
  payloads = [pkgs.nginx pkgs.envoy pkgs.k3s-worker observer.package];
  companions = lib.concatMap (package: [package.deploymentArtifact package.documentationArtifact]) payloads;
in {
  name = "runtime-module-composition";
  timeout = 2400;
  bootTimeout = 600;
  systemReadyTimeout = 0;
  qualification =
    selectedFixture.qualification
    // {
      extraClosures =
        selectedFixture.qualification.extraClosures
        ++ payloads
        ++ companions
        ++ additionalClosures
        ++ [
          pkgs.aos.testSupport
          pkgs.coreutils
          pkgs.curl
          pkgs.grep
          pkgs.jq
          pkgs.nix
          pkgs.util-linux
        ];
    };
  machines.runtime = {
    system = runtimeSystem;
    memoryMiB = 4096;
    varSizeMiB = 4096;
    extraClosures =
      payloads
      ++ companions
      ++ additionalClosures
      ++ [
        pkgs.aos
        pkgs.aos.apm
        pkgs.coreutils
        pkgs.curl
        pkgs.grep
        pkgs.jq
        pkgs.nix
        pkgs.util-linux
      ];
    packages = ["aos-test-agent" "envoy" "k3s-worker"];
    metadata."host.nix" = ''
      { lib, ... }: {
        ${observer.hostModule}
        ${extraHostModule}
        aos.networking.hostName = "runtime-modules";
      }
    '';
  };
  testScript =
    # python
    ''
      import base64
      import hashlib
      import json
      import shlex

      APM = ${
        if qualificationImage
        then ''runtime.guest_tool("apm")''
        else builtins.toJSON "${pkgs.aos.apm}/bin/apm"
      }
      AOS = ${
        if qualificationImage
        then ''runtime.guest_tool("aos")''
        else builtins.toJSON "${pkgs.aos}/bin/aos"
      }
      COREUTILS = "${pkgs.coreutils}/bin"
      CURL = "${pkgs.curl}/bin/curl"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      OBSERVER_CONTROLLER = "${observer.controller}/bin/aos-ability-boundary-controller"
      PROFILE = "/var/lib/profiles/system"
      JOURNAL = f"{PROFILE}/deployment/effects.journal"
      WORKTREE = "/var/lib/aos/runtime-module-worktree"
      BOUNDARY_ROOT = "${observer.settings.stateRoot}"
      TARGET = f"{BOUNDARY_ROOT}/target.json"
      HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
      RESUMED_EVENT = f"{BOUNDARY_ROOT}/resumed-event.json"
      CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
      EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
      RECOVERY_FINDINGS = {}
      EXTRA_MODULE = ${builtins.toJSON extraHostModule}
      NATIVE_IDENTITY_FIELDS = ("transaction", "effect", "revision", "action", "journal_sequence")

      def read_json(path):
          return json.loads(runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}"))

      def write_file(path, content):
          encoded = base64.b64encode(content.encode()).decode()
          runtime.succeed(f"printf '%s' {shlex.quote(encoded)} | {COREUTILS}/base64 -d > {shlex.quote(path)}")
          runtime.succeed(f"{COREUTILS}/chmod 0600 {shlex.quote(path)}")

      def write_canonical(path, value):
          payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
          runtime.succeed(f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} {payload.hex()}")

      def current_generation():
          selected = runtime.succeed(f"{COREUTILS}/readlink {PROFILE}/current").strip()
          return int(selected.rsplit("gen-", 1)[1])

      def diagnostic():
          document = json.loads(runtime.succeed(
              f"{AOS} ability diagnostic {PROFILE} {current_generation()} --audience deployment"
          ))
          assert document["liveStateVerified"] is False, document
          return document

      def inspection():
          document = json.loads(runtime.succeed(f"{AOS} ability journal {JOURNAL} --format json"))
          assert document["schema"] == "aos.activation.inspection", document
          assert document["liveStateVerified"] is False, document
          assert document["incompleteTailBytes"] == 0, document
          return document

      def graph():
          document = diagnostic()["desired"]["graph"]
          assert document["schema"] == "aos.activation.graph", document
          return document

      def effect_id(ability, operation, instance):
          matches = [key for key, node in graph()["nodes"].items()
              if node["identity"][-3:] == [ability, operation, instance]]
          assert len(matches) == 1, (ability, operation, instance, matches)
          return matches[0]

      def apply(label, dry_run=False):
          flag = " --dry-run" if dry_run else ""
          runtime.succeed(
              f"{APM} switch --worktree {WORKTREE} --eval-root /var/lib/aos/runtime-evaluations/{label}{flag}",
              timeout=1200,
          )

      def route():
          return runtime.succeed(f"{CURL} --fail --silent http://127.0.0.1:18080/health")

      def check_services(expected):
          runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet nginx.service", timeout=180)
          runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet envoy.main.service", timeout=180)
          assert route() == expected
          assert runtime.succeed(f"{CURL} --fail --silent http://127.0.0.1:18081/health") == "envoy-runtime"
          runtime.fail(f"{SYSTEMCTL} is-active --quiet k3s.service")
          assert runtime.succeed(f"{COREUTILS}/cat /etc/runtime-modules/operator.conf").strip() == "authority=runtime"

      def payload_hash(path):
          return runtime.succeed(f"{NIX_STORE} --dump {shlex.quote(path)} | {COREUTILS}/sha256sum").split()[0]

      def assert_payloads_immutable():
          for name, path in PAYLOADS.items():
              assert payload_hash(path) == PAYLOAD_HASHES[name], name

      def wait_selection(path, sequence):
          runtime.wait_until_succeeds(
              f"{JQ} -e --arg sequence {shlex.quote(sequence)} '.sequence == $sequence' {shlex.quote(path)}",
              timeout=600,
          )
          selected = read_json(path)
          assert selected["event"]["schema"] == "aos.activation.boundary", selected
          return selected

      def start_candidate(unit):
          runtime.succeed(f"{SYSTEMCTL} reset-failed {unit} 2>/dev/null || true")
          runtime.succeed(
              f"{SYSTEMD_RUN} --quiet --unit={unit} --property=Type=exec "
              f"{APM} switch --worktree {WORKTREE} --eval-root /var/lib/aos/runtime-evaluations/{unit}",
              timeout=180,
          )

      def retain_recovery(sequence, held, resumed, before, after, previous_response, response):
          for field in NATIVE_IDENTITY_FIELDS:
              assert resumed["event"][field] == held["event"][field], (field, held, resumed)
          assert resumed["event"]["boundary"] == "observation-returned", resumed
          records = [record for record in after["records"]
              if record.get("dispatch") and record["transaction"] == held["event"]["transaction"]
              and record["dispatch"]["effect"] == held["event"]["effect"]
              and record["dispatch"]["revision"] == held["event"]["revision"]
              and record["dispatch"]["journalSequence"] == held["event"]["journal_sequence"]]
          assert [record["event"] for record in records] == ["started", "finished"], records
          assert records[0]["sequence"] == held["event"]["journal_sequence"], records
          assert after["pending"] is None and after["completed"] is not None, after
          assert route() == response
          observed = [json.loads(line) for line in runtime.succeed(f"{COREUTILS}/cat {EVENTS}").splitlines()]
          matching = [event for event in observed if all(event[field] == held["event"][field] for field in NATIVE_IDENTITY_FIELDS)]
          assert [event["boundary"] for event in matching].count("dispatch-returned") == 1, matching
          RECOVERY_FINDINGS[sequence] = {
              "held": held, "resumed": resumed, "before": before,
              "after": after, "records": records, "boundaries": matching,
              "substrate": {"beforeResponse": previous_response, "afterResponse": route()},
          }

      def interrupted_update(sequence, response, power_loss=False):
          previous_response = route()
          selected_effect = effect_id("configuration", "file", "nginx")
          select_response(response)
          runtime.succeed(f"{COREUTILS}/rm -f {HELD_EVENT} {RESUMED_EVENT} {CONTINUE}")
          write_canonical(TARGET, {
              "action": "disconnect", "boundary": "dispatch-returned",
              "effect": selected_effect, "invocation_action": "apply", "sequence": sequence,
          })
          unit = "aos-native-" + sequence
          prior_generation = current_generation()
          start_candidate(unit)
          held = wait_selection(HELD_EVENT, sequence)
          assert held["event"]["effect"] == selected_effect, held
          assert held["event"]["boundary"] == "dispatch-returned", held
          assert current_generation() == prior_generation
          assert response in runtime.succeed(f"{COREUTILS}/cat /etc/nginx/nginx.conf")
          assert route() == previous_response

          if power_loss:
              boot_id = runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip()
              # Recovery may finish while the machine reconnects. The controller
              # still retains its exact returned observation before acknowledging.
              write_canonical(CONTINUE, {"sequence": sequence})
              runtime.power_cycle(timeout=600)
              assert runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip() != boot_id
              resumed = wait_selection(RESUMED_EVENT, sequence)
              before = None
          else:
              runtime.succeed(f"{SYSTEMCTL} kill --signal=KILL --kill-whom=all {unit}")
              runtime.wait_until_succeeds(f"! {SYSTEMCTL} is-active --quiet {unit}", timeout=180)
              before = inspection()
              assert before["pending"]["effect"] == selected_effect, before
              assert before["pending"]["journalSequence"] == held["event"]["journal_sequence"], before
              start_candidate(unit)
              resumed = wait_selection(RESUMED_EVENT, sequence)
              write_canonical(CONTINUE, {"sequence": sequence})
              runtime.wait_until_succeeds(
                  f"test \"$({SYSTEMCTL} show --property=Result --value {unit})\" = success "
                  f"&& ! {SYSTEMCTL} is-active --quiet {unit}", timeout=1200,
              )
          runtime.wait_until_succeeds(f"{CURL} --fail --silent http://127.0.0.1:18080/health | {pkgs.grep}/bin/grep -Fx {shlex.quote(response)}", timeout=300)
          after = inspection()
          retain_recovery(sequence, held, resumed, before, after, previous_response, response)
          runtime.succeed(f"{COREUTILS}/rm -f {TARGET}")
          check_services(response)
          assert_payloads_immutable()

      runtime.wait_for_unit("aos-activate.service", timeout=600)
      runtime.wait_for_unit("aos-ability-boundary-controller.service", timeout=180)
      runtime.succeed("test -S /run/aos-instrumentation/controller.sock")
      PAYLOADS = ${builtins.toJSON {
        nginx = toString pkgs.nginx;
        envoy = toString pkgs.envoy;
      }}
      PAYLOAD_HASHES = {name: payload_hash(path) for name, path in PAYLOADS.items()}
      runtime.succeed(f"{COREUTILS}/install -d -m 0700 {WORKTREE}")
      packages_source = """{ config, ... }: {
        aos.abilities.configuration.operations.file.effects.runtime-operator.input = {
          path = "/etc/runtime-modules/operator.conf";
          content = "authority=runtime\\n";
          mode = "0444";
        };
      }"""
      services_source = """{
        aos.services.nginx = {
          enable = true;
          virtualHosts.runtime = {
            listen = [18080];
            serverNames = ["localhost"];
            locations."/health"."return" = {code = 200; body = "nginx-runtime";};
          };
        };
        aos.envoy = {
          enable = true;
          listeners.runtime = {
            address = "127.0.0.1";
            port = 18081;
            filterChains.http.virtualHosts.runtime = {
              domains = ["*"];
              routes.health = {
                match.path = "/health";
                match.prefix = null;
                directResponse = {status = 200; body = "envoy-runtime";};
              };
            };
          };
        };
        aos.k3s.enable = false;
      }"""
      write_file(f"{WORKTREE}/10-packages.nix", packages_source)
      write_file(f"{WORKTREE}/20-services.nix", services_source)
      if EXTRA_MODULE:
          write_file(f"{WORKTREE}/30-instrumentation.nix", "{lib, ...}: {" + EXTRA_MODULE + "}")
      initial_generation = current_generation()
      apply("preview", dry_run=True)
      assert current_generation() == initial_generation
      runtime.fail("test -e /etc/runtime-modules/operator.conf")
      apply("configured")
      check_services("nginx-runtime")
      assert_payloads_immutable()

      def select_response(response):
          write_file(f"{WORKTREE}/20-services.nix", services_source.replace('body = "nginx-runtime";', 'body = ' + json.dumps(response) + ';'))

      process_id = runtime.succeed(f"{SYSTEMCTL} show --property=MainPID --value nginx.service").strip()
      invocation_id = runtime.succeed(f"{SYSTEMCTL} show --property=InvocationID --value nginx.service").strip()
      select_response("nginx-runtime-reloaded")
      apply("reloaded")
      check_services("nginx-runtime-reloaded")
      assert runtime.succeed(f"{SYSTEMCTL} show --property=MainPID --value nginx.service").strip() == process_id
      assert runtime.succeed(f"{SYSTEMCTL} show --property=InvocationID --value nginx.service").strip() == invocation_id

      # Admission rejects an invalid ordinary module before publishing a new
      # generation or mutating the running service and its configuration.
      prior_generation = current_generation()
      write_file(f"{WORKTREE}/99-invalid.nix", '{ aos.services.nginx.virtualHosts.runtime.listen = [70000]; }')
      runtime.fail(f"{APM} switch --worktree {WORKTREE} --eval-root /var/lib/aos/runtime-evaluations/rejected", timeout=600)
      assert current_generation() == prior_generation
      check_services("nginx-runtime-reloaded")
      runtime.succeed(f"{COREUTILS}/rm {WORKTREE}/99-invalid.nix")

      interrupted_update("process-loss", "nginx-runtime-process-loss")
      interrupted_update("power-loss", "nginx-runtime-power-loss", power_loss=True)

      # Replay uses admitted immutable module sources, not dirty operator files.
      committed = current_generation()
      committed_descriptor = runtime.succeed(f"{COREUTILS}/readlink -f {PROFILE}/current/evaluation.json").strip()
      select_response("dirty-worktree-must-not-run")
      runtime.reboot(timeout=600)
      runtime.wait_for_unit("aos-activate.service", timeout=600)
      check_services("nginx-runtime-power-loss")
      assert runtime.succeed(f"{COREUTILS}/readlink -f {PROFILE}/current/evaluation.json").strip() == committed_descriptor
      assert current_generation() >= committed
      assert_payloads_immutable()

      # A manager reload may partially mutate before returning failure. The
      # generic service observer cannot prove the daemon state from process
      # identity alone, so clearing the fault still leaves this intent unknown.
      prior_generation = current_generation()
      runtime.succeed(f"{COREUTILS}/install -d -m 0755 /run/systemd/system/nginx.service.d")
      write_file("/run/systemd/system/nginx.service.d/99-fail-reload.conf", "[Service]\nExecReload=\nExecReload=${pkgs.coreutils}/bin/false\n")
      runtime.succeed(f"{SYSTEMCTL} daemon-reload")
      select_response("nginx-runtime-failed-reload")
      runtime.fail(f"{APM} switch --worktree {WORKTREE} --eval-root /var/lib/aos/runtime-evaluations/failed-reload", timeout=1200)
      assert current_generation() == prior_generation
      assert route() == "nginx-runtime-power-loss"
      assert "nginx-runtime-failed-reload" in runtime.succeed(f"{COREUTILS}/cat /etc/nginx/nginx.conf")
      failed = inspection()
      assert failed["pending"] is not None, failed
      runtime.succeed(f"{COREUTILS}/rm /run/systemd/system/nginx.service.d/99-fail-reload.conf")
      runtime.succeed(f"{SYSTEMCTL} daemon-reload")
      runtime.fail(f"{APM} switch --worktree {WORKTREE} --eval-root /var/lib/aos/runtime-evaluations/retry-unknown-reload", timeout=1200)
      assert inspection()["pending"] == failed["pending"]
      assert current_generation() == prior_generation
      assert route() == "nginx-runtime-power-loss"

    '';
}
