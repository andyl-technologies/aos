##! Runtime module-set and package configuration acceptance.
##!
##! This suite deliberately keeps the cloud-delivered platform host module
##! small, then applies two independently authored runtime fragments. The
##! fragments select and configure package-owned nginx, Envoy, and k3s
##! interfaces through the production on-host evaluator. The test also proves
##! that failed candidates do not disturb the current generation and that a
##! reboot consumes the retained immutable module set rather than the dirty
##! authoring worktree.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  observerForwardEndpoint ? null,
  extraRuntimeModules ? [],
  extraHostModule ? "",
  additionalClosures ? [],
  ...
}: let
  observerFixture = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
    forwardEndpoint = observerForwardEndpoint;
  };
  runtimeSystem = mkSystem (
    [
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
        };

        imports = [observerFixture.module];
      }
    ]
    ++ extraRuntimeModules
  );
  bootInitrdIdentityModule = {config, ...}: {
    environment.etc."aos/fleet-boot-initrd".text = ''
      ${config.system.build.initrd}/initrd.img
    '';
  };
in {
  name = "runtime-module-composition";
  timeout = 1800;
  # The full fleet umbrella boots many KVM guests concurrently. Initial host
  # evaluation can legitimately exceed the generic 180-second readiness
  # deadline under that load, before this test's own bounded apply steps begin.
  bootTimeout = 600;
  systemReadyTimeout = 0;

  machines.runtime = {
    system = runtimeSystem;
    extraModules = [bootInitrdIdentityModule];
    memoryMiB = 4096;
    varSizeMiB = 2048;
    packages = [
      "aos-test-agent"
      "envoy"
      "k3s-worker"
    ];
    extraClosures = [
      pkgs.diffutils
      pkgs.findutils
      pkgs.git
      pkgs.grep
      pkgs.nix
      pkgs.util-linux
      observerFixture.package
    ]
    ++ additionalClosures;
    metadata."host.nix" = ''
      { lib, ... }: {
        ${observerFixture.hostModule}
        ${extraHostModule}

        aos.networking.hostName = "runtime-modules";

        environment.etc."runtime-modules/platform.conf" = {
          text = "authority=platform\n";
          mode = "0644";
        };

        # This fixture deliberately installs nginx through APM. Its signed
        # service manifest requests host networking and a bounded capability,
        # so exercise the production admission path with an explicit host
        # policy rather than bypassing permission checks.
        environment.etc."aos/policy.toml" = {
          text = "tier = \"privileged\"\n";
          mode = "0644";
        };
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
      import textwrap
      from pathlib import Path

      APM = "${pkgs.aos.apm}/bin/apm"
      APR = "${pkgs.aos.apr}/bin/apr"
      AOS = "${pkgs.aos}/bin/aos"
      CURL = "${pkgs.curl}/bin/curl"
      COREUTILS = "${pkgs.coreutils}/bin"
      FIND = "${pkgs.findutils}/bin/find"
      FLOCK = "${pkgs.util-linux}/bin/flock"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      SHA256SUM = "${pkgs.coreutils}/bin/sha256sum"
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      XDG_CACHE_HOME = "/var/cache/aos-runtime-module-test"
      BOUNDARY_ROOT = "/var/lib/aos/ability-boundary-test"
      CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
      EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
      HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
      RESUMED_EVENT = f"{BOUNDARY_ROOT}/resumed-event.json"
      TARGET = f"{BOUNDARY_ROOT}/target.json"
      OBSERVER_CONTROLLER = (
          "${observerFixture.controller}/bin/aos-ability-boundary-controller"
      )
      PACKAGE_RUNTIME = (
          "${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped"
      )
      OBSERVER_FORWARD_ENABLED = ${
        if observerForwardEndpoint == null
        then "False"
        else "True"
      }


      def wait_for_activation():
          runtime.wait_until_succeeds(
              "test -s /run/aos/manifest.json "
              "&& test -s /run/aos/graph.json "
              "&& test -s /run/aos/activation.json",
              timeout=300,
          )
          runtime.wait_until_succeeds(
              "systemctl is-active --quiet aos-config.target", timeout=300
          )


      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def write_file(path, contents):
          encoded = base64.b64encode(contents.encode()).decode()
          runtime.succeed(
              f"printf '%s' '{encoded}' | base64 -d > '{path}'"
          )


      def read_json(path):
          return json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(path)}"
          ))


      def write_canonical(path, value):
          payload = json.dumps(
              value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
          ).encode()
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} "
              f"{payload.hex()}"
          )


      def operation_matches_selector(operation, selector):
          resource = operation["target"]["resource"]
          return (
              operation["interface"]["name"] == selector["interface"]
              and operation["method"] == selector["method"]
              and resource["provider"]["key"] == selector["provider_key"]
              and resource["key"] == selector["resource_key"]
          )


      def selector_for(operation):
          resource = operation["target"]["resource"]
          return {
              "interface": operation["interface"]["name"],
              "method": operation["method"],
              "provider_key": resource["provider"]["key"],
              "resource_key": resource["key"],
          }


      def activation_state(generation):
          generation_root = f"/var/lib/profiles/system/gen-{generation}"
          activation = read_json(f"{generation_root}/activation.json")
          transaction = activation["native_ability_transaction"]
          transaction_root = f"{generation_root}/ability-transactions/{transaction}"
          bundle_path = f"{transaction_root}/plan-bundle.json"
          bundle_bytes = runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(bundle_path)}"
          ).encode()
          bundle = json.loads(bundle_bytes)
          operations = bundle["transition"]["effect_document"]["operations"]
          operation_by_key = {
              json.dumps(operation["key"], sort_keys=True): (ordinal, operation)
              for ordinal, operation in enumerate(operations)
          }
          pairs = []
          for edge in bundle["transition"]["effect_document"]["edges"]:
              if edge["kind"] != "required-success":
                  continue
              source = operation_by_key.get(
                  json.dumps(edge["from"].get("key"), sort_keys=True)
              )
              target = operation_by_key.get(
                  json.dumps(edge["to"].get("key"), sort_keys=True)
              )
              if source is None or target is None:
                  continue
              if source[1]["method"] == "materialize" and target[1]["method"] == "update":
                  pairs.append((source, target, edge))
          assert len(pairs) == 1, (pairs, bundle)
          publish, dependent, edge = pairs[0]
          return {
              "activation": activation,
              "bundle": bundle,
              "bundle_bytes": bundle_bytes,
              "dependent": dependent,
              "edge": edge,
              "generation": generation,
              "plan": bundle["plan"],
              "publish": publish,
              "root": transaction_root,
              "transaction": transaction,
          }


      def arm_boundary(sequence, selector):
          runtime.succeed(
              f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
              f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
          )
          write_canonical(TARGET, {
              "action": "disconnect",
              "boundary": "effect-returned",
              "purpose": "effect",
              "sequence": sequence,
              **selector,
          })


      def held_boundary(sequence, selector):
          runtime.wait_until_succeeds(
              f"test -s {shlex.quote(HELD_EVENT)}", timeout=300
          )
          held = read_json(HELD_EVENT)
          event = held["event"]
          assert held["sequence"] == sequence, held
          assert event["boundary"] == "effect-returned", held
          assert event["purpose"] == "effect", held
          assert event["cancelled"] is False, held
          assert operation_matches_selector(
              event["operation"]["operation"], selector
          ), held
          if OBSERVER_FORWARD_ENABLED:
              assert held["forwarded_acknowledgement"] == {
                  "action": "continue",
                  "event_digest": held["event_digest"],
                  "schema": "aos.ability-execution-boundary-ack/v1",
              }, held
          return held


      def resumed_boundary(sequence, selector, transaction, plan):
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
          assert operation_matches_selector(
              event["operation"]["operation"], selector
          ), resumed
          if OBSERVER_FORWARD_ENABLED:
              assert resumed["forwarded_acknowledgement"] == {
                  "action": "continue",
                  "event_digest": resumed["event_digest"],
                  "schema": "aos.ability-execution-boundary-ack/v1",
              }, resumed
          return resumed


      def release_reconciliation(sequence):
          write_canonical(CONTINUE, {"sequence": sequence})


      def start_apply(unit, eval_root):
          runtime.succeed(
              f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
              f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} "
              "--property=Type=exec "
              f"--setenv=XDG_CACHE_HOME={XDG_CACHE_HOME} "
              f"{APM} config apply --eval-root {shlex.quote(eval_root)}"
          )


      def wait_apply(unit, success):
          runtime.wait_until_succeeds(
              f"state=$({SYSTEMCTL} show -p ActiveState --value "
              f"{shlex.quote(unit)}); test \"$state\" = inactive -o \"$state\" = failed",
              timeout=600,
          )
          status = runtime.succeed(
              f"{SYSTEMCTL} show -p ExecMainStatus --value {shlex.quote(unit)}"
          ).strip()
          assert (status == "0") == success, (unit, status, runtime.succeed(
              f"journalctl -u {shlex.quote(unit)} --no-pager 2>&1 || true"
          ))


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


      def disable_automatic_activation_recovery():
          drop_in_directory = "/run/systemd/system/aos-activate.service.d"
          drop_in = f"{drop_in_directory}/90-runtime-recovery-test.conf"
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


      def authority_assignment_key(assignment):
          return json.dumps({
              "implementation": assignment["implementation"],
              "interface": assignment["interface"],
              "provider": assignment["provider"],
          }, separators=(",", ":"), sort_keys=True)


      def assert_fresh_receiving_authority(before, after, plan):
          for field in (
              "schema", "policy_fence", "policy_revision", "resolution_policy",
              "platform_policy", "transition_authority", "plan", "bindings",
          ):
              assert after[field] == before[field], (field, before, after)
          assert after["plan"] == plan, after
          before_assignments = {
              authority_assignment_key(assignment): assignment
              for assignment in before["provider_assignments"]
          }
          after_assignments = {
              authority_assignment_key(assignment): assignment
              for assignment in after["provider_assignments"]
          }
          assert after_assignments, after
          assert after_assignments.keys() <= before_assignments.keys(), (
              before_assignments, after_assignments,
          )
          for key, assignment in after_assignments.items():
              assert assignment["incarnation"] != before_assignments[key]["incarnation"], (
                  before_assignments[key], assignment,
              )


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


      def retained_host_handoff(generation):
          path = (
              f"/var/lib/profiles/system/gen-{generation}/toplevel/initrd/"
              "initrd-stage-contract.json"
          )
          contract_bytes = runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(path)}"
          ).encode()
          contract = json.loads(contract_bytes)
          handoff = contract["handoff"]
          assert contract["schema_version"] == "aos.boot.initrd-stage-contract/v1"
          assert contract["stage"] == "initrd"
          assert handoff["to_stage"] == "host"
          assert handoff["mechanism"] == "systemd-switch-root"
          assert handoff["transferable_handles"] is False
          assert handoff["receiving_stage_reauthorizes"] is True
          assert handoff["receiving_stage_reacquires"] is True
          assert {
              "initrd_path": "/sysroot/var/lib/profiles/system",
              "host_path": "/var/lib/profiles/system",
          } in handoff["durable_state_roots"]
          return contract_bytes


      def actual_boot_initrd_identity(expected_path):
          assert runtime.boot == "kernel", runtime.boot
          assert runtime.initrd_path == expected_path, (
              runtime.initrd_path, expected_path,
          )
          initrd_path = Path(runtime.initrd_path)
          contract_path = initrd_path.parent / "initrd-stage-contract.json"
          contract_bytes = contract_path.read_bytes()
          contract = json.loads(contract_bytes)
          digest = hashlib.sha256()
          with initrd_path.open("rb") as initrd_file:
              for chunk in iter(lambda: initrd_file.read(1024 * 1024), b""):
                  digest.update(chunk)
          assert contract["artifact"] == {
              "path": "initrd.img",
              "sha256": f"sha256:{digest.hexdigest()}",
              "size_bytes": initrd_path.stat().st_size,
          }, contract
          return runtime.initrd_path, contract_bytes


      def apply_worktree(eval_root, dry_run=False):
          dry_run_flag = " --dry-run" if dry_run else ""
          runtime.succeed(
              f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config apply{dry_run_flag} "
              f"--eval-root '{eval_root}'",
              timeout=600,
          )


      def wait_for_service(unit):
          try:
              runtime.wait_until_succeeds(
                  f"systemctl is-active --quiet {unit}", timeout=120
              )
          except Exception:
              print(runtime.succeed(
                  f"systemctl status --no-pager --full {unit} || true; "
                  f"journalctl --no-pager -u {unit} -n 100 || true"
              ))
              raise


      def assert_package_configuration(nginx_expected="nginx-runtime"):
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/platform.conf)\" = authority=platform"
          )
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/operator.conf)\" = authority=runtime"
          )

          wait_for_service("nginx.service")
          nginx_body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:18080/health"
          )
          assert nginx_body == nginx_expected, nginx_body
          runtime.succeed("grep -q 'listen 18080;' /etc/nginx/nginx.conf")

          wait_for_service("envoy.service")
          envoy_body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:18081/health"
          )
          assert envoy_body == "envoy-runtime", envoy_body
          runtime.succeed(
              f"{JQ} -e '.static_resources.listeners | length == 1' "
              "/etc/aos/packages/envoy/bootstrap.json"
          )

          # A worker without a real control plane remains declarable while its
          # native ability requests stay absent.
          runtime.fail("systemctl is-active --quiet k3s.service")
          runtime.fail("test -e /etc/aos/packages/k3s-worker")


      def payload_nar_hash(path):
          return runtime.succeed(
              f"{NIX_STORE} --dump '{path}' | {SHA256SUM}"
          ).split()[0]


      def assert_payloads_immutable():
          assert payload_nar_hash("${pkgs.nginx}") == payload_hashes["nginx"]
          assert payload_nar_hash("${pkgs.envoy}") == payload_hashes["envoy"]


      wait_for_activation()
      runtime.succeed("systemctl is-active --quiet multi-user.target")
      runtime.wait_for_unit(
          "aos-ability-boundary-controller.service", timeout=180
      )
      runtime.succeed("test -S /run/aos-instrumentation/controller.sock")
      runtime.succeed(f"install -d -m 0700 {XDG_CACHE_HOME}")
      expected_boot_initrd = runtime.succeed(
          f"{COREUTILS}/cat /etc/aos/fleet-boot-initrd"
      ).strip()
      boot_initrd_identity_before = actual_boot_initrd_identity(
          expected_boot_initrd
      )
      platform_hash = runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0]
      initial = current_generation()
      initial_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{initial}/manifest.json"
      ))
      platform_host_input = initial_manifest["inputs"]["host_nix"]
      platform_facts_input = initial_manifest["inputs"]["instance_facts"]
      payload_hashes = {
          "nginx": payload_nar_hash("${pkgs.nginx}"),
          "envoy": payload_nar_hash("${pkgs.envoy}"),
      }

      status = runtime.succeed(f"{APM} config status 2>&1")
      assert "active runtime modules: empty" in status, status

      # Nginx is bundled in the immutable image but deliberately absent from
      # the seeded package profile. Publish its package/expose pair into a
      # local authenticated registry and select it through public APM before
      # supplying any operator configuration module.
      runtime.fail(
          f"HOME=/tmp USER=root {APM} list --system --installed "
          "2>&1 | grep -q '^nginx'"
      )
      runtime.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/runtime-publisher
          export USER=root
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export GIT_AUTHOR_NAME=Test
          export GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test
          export GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/runtime-nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\n' \
            > "$NIX_CONF_DIR/nix.conf"

          {APR} keys generate release --registry runtime-reg \
            > /tmp/runtime-keygen.out 2>&1
          PUBKEY=$(awk '/Public key:/ {{print $NF; exit}}' /tmp/runtime-keygen.out)
          KEY=$HOME/.config/apm/keys/runtime-reg-release.key
          {APR} create runtime-reg \
            --trust-key "$PUBKEY" \
            --trust-key-id release \
            --key "$KEY"
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/runtime-reg.toml" <<EOF
          [registry]
          name = "runtime-reg"
          url = "file://$HOME/.local/share/apm/registries/runtime-reg"

          [registry.signing_keys]
          release = "$KEY"

          [registry.signing]
          root_owner_signers = ["release"]
          EOF

          {APR} publish '${pkgs.nginx}' \
            --name nginx \
            --version '${pkgs.nginx.version}' \
            --description 'runtime module acceptance fixture' \
            --license BSD-2-Clause \
            --maintainer test \
            --expose-manifest '${pkgs.nginx.expose}/manifest.json' \
            --config-module '${pkgs.nginx.config}' \
            --config-base-lib '${runtimeSystem.config.aos.config.evalAtBoot.baseLib}' \
            --registry runtime-reg \
            --key-id release

          REG_DIR=$HOME/.local/share/apm/registries/runtime-reg
          mkdir -p /var/lib/runtime-module-registry-cache
          {APR} release '${pkgs.nginx.version}' \
            --registry runtime-reg \
            --key-id release \
            --cache-url file:///var/lib/runtime-module-registry-cache \
            --upload-url file:///var/lib/runtime-module-registry-cache

          HOME=/tmp USER=root {APM} registry --system add \
            "file://$REG_DIR" \
            --name runtime-reg \
            --version '=${pkgs.nginx.version}' \
            --trust-key "$PUBKEY" \
            --no-clone
          printf 'root_owner_signers = ["release"]\\n' \
            >> /var/lib/apm/config/registries.d/runtime-reg.toml
          HOME=/tmp USER=root {APM} update \
            --system --registry runtime-reg

          cat > /run/runtime-module-desired.toml <<'EOF'
          packages = ["nginx", "envoy", "k3s-worker"]
          EOF
          HOME=/tmp USER=root {APM} install --system \
            --from /run/runtime-module-desired.toml --yes

      """), timeout=1200)
      installed = runtime.succeed(
          f"HOME=/tmp USER=root {APM} list --system --installed 2>&1"
      )
      assert "nginx" in installed, installed

      runtime.succeed("install -d -m 0700 /run/runtime-module-fixtures")
      packages_module = """{
        aos.apm.desiredPackages = [ "nginx" "envoy" "k3s-worker" ];
        environment.etc."runtime-modules/operator.conf" = {
          text = "authority=runtime\\n";
          mode = "0644";
        };
      }
      """
      services_module = """{
        nginx = {
          enable = true;
          virtualHosts.runtime = {
            listen = [ 18080 ];
            serverNames = [ "localhost" ];
            locations."/health"."return" = {
              code = 200;
              body = "nginx-runtime";
            };
          };
        };

        envoy = {
          enable = true;
          listeners.runtime = {
            address = "127.0.0.1";
            port = 18081;
            filterChains.http.virtualHosts.runtime = {
              domains = [ "*" ];
              routes.health = {
                match.path = "/health";
                match.prefix = null;
                directResponse = {
                  status = 200;
                  body = "envoy-runtime";
                };
              };
            };
          };
        };

        k3s = {
          enable = false;
          node.name = "runtime-worker";
          networking.flannelBackend = "wireguard-native";
        };
      }
      """
      write_file(
          "/run/runtime-module-fixtures/10-packages.nix", packages_module
      )
      write_file(
          "/run/runtime-module-fixtures/20-services.nix", services_module
      )
      runtime.fail(
          f"{APM} config add /run/runtime-module-fixtures/10-packages.nix "
          "--name 'bad;name.nix'"
      )
      runtime.fail(
          "test -e '/var/lib/aos/config/modules.d/bad;name.nix'"
      )
      runtime.succeed(f"""
          {APM} config add /run/runtime-module-fixtures/10-packages.nix
          {APM} config add /run/runtime-module-fixtures/20-services.nix
      """)
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert "worktree: /var/lib/aos/config/modules.d (2 entrypoints)" in status, status

      # `diff` and `apply --dry-run` use the same full fixpoint as activation
      # but must leave both the current pointer and live files untouched.
      runtime.succeed(
          f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config diff "
          "--eval-root /run/runtime-module-composition-diff",
          timeout=600,
      )
      apply_worktree("/run/runtime-module-composition-dry-run", dry_run=True)
      assert current_generation() == initial
      runtime.fail("test -e /etc/runtime-modules/operator.conf")

      apply_worktree("/run/runtime-module-composition-switch")
      configured = current_generation()
      assert configured != initial, (initial, configured)
      assert_package_configuration()
      assert_payloads_immutable()

      # Change only nginx's rendered configuration. The package-owned service
      # declaration requests reload for configuration changes, so the selected
      # systemd provider must preserve the running process while the new route
      # becomes observable.
      nginx_invocation = runtime.succeed(
          "systemctl show -p InvocationID --value nginx.service"
      ).strip()
      nginx_pid = runtime.succeed(
          "systemctl show -p MainPID --value nginx.service"
      ).strip()
      updated_services_module = services_module.replace(
          'body = "nginx-runtime";',
          'body = "nginx-runtime-reloaded";',
      )
      write_file(
          "/run/runtime-module-fixtures/20-services-updated.nix",
          updated_services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-updated.nix"
      )
      apply_worktree("/run/runtime-module-composition-reload")
      reloaded = current_generation()
      assert reloaded != configured, (configured, reloaded)
      assert_package_configuration("nginx-runtime-reloaded")
      assert runtime.succeed(
          "systemctl show -p InvocationID --value nginx.service"
      ).strip() == nginx_invocation
      assert runtime.succeed(
          "systemctl show -p MainPID --value nginx.service"
      ).strip() == nginx_pid
      nginx_consumer_receipts = runtime.succeed(
          "ls -1 /etc/aos/ability-consumers/nginx.service/sha256"
      ).splitlines()
      assert len(nginx_consumer_receipts) == 1, nginx_consumer_receipts
      assert_payloads_immutable()

      # Force the selected service manager's reload operation to fail after
      # configuration publication. The configuration generation and bytes must
      # remain published, while the separately tracked consumer revision stays
      # unknown and the old process continues serving its prior route.
      runtime.succeed(f"""
          install -d -m 0755 /run/systemd/system/nginx.service.d
          cat > /run/systemd/system/nginx.service.d/99-fail-reload.conf <<'EOF'
          [Service]
          ExecReload=
          ExecReload={COREUTILS}/bin/false
          EOF
          systemctl daemon-reload
      """)
      failed_services_module = services_module.replace(
          'body = "nginx-runtime";',
          'body = "nginx-runtime-failed-reload";',
      )
      write_file(
          "/run/runtime-module-fixtures/20-services-failed-reload.nix",
          failed_services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-failed-reload.nix"
      )
      status, stdout, stderr = runtime.execute(
          f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config apply "
          "--eval-root /run/runtime-module-composition-failed-reload",
          timeout=600,
      )
      assert status != 0, (stdout, stderr)
      failed_reload = current_generation()
      assert failed_reload != reloaded, (reloaded, failed_reload)
      assert runtime.succeed(
          "systemctl show -p InvocationID --value nginx.service"
      ).strip() == nginx_invocation
      assert runtime.succeed(
          "systemctl show -p MainPID --value nginx.service"
      ).strip() == nginx_pid
      runtime.succeed("grep -q 'nginx-runtime-failed-reload' /etc/nginx/nginx.conf")
      nginx_body = runtime.succeed(
          f"{CURL} --fail --silent http://127.0.0.1:18080/health"
      )
      assert nginx_body == "nginx-runtime-reloaded", nginx_body
      assert runtime.succeed(
          "ls -1 /etc/aos/ability-consumers/nginx.service/sha256"
      ).splitlines() == nginx_consumer_receipts

      activation = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{failed_reload}/activation.json"
      ))
      assert activation["status"] == "native-failed", activation
      assert activation["activation_exit"] == 6, activation
      assert activation["native_ability_prior_generation"] == reloaded, activation
      transaction = activation["native_ability_transaction"]
      transaction_root = (
          f"/var/lib/profiles/system/gen-{failed_reload}/ability-transactions/"
          f"{transaction}"
      )
      bundle = json.loads(runtime.succeed(
          f"cat {transaction_root}/plan-bundle.json"
      ))
      effect = bundle["transition"]["effect_document"]
      operations = effect["operations"]
      operation_by_key = {
          json.dumps(operation["key"], sort_keys=True): (ordinal, operation)
          for ordinal, operation in enumerate(operations)
      }
      configuration_service_pairs = []
      for edge in effect["edges"]:
          if edge["kind"] != "required-success":
              continue
          source = operation_by_key.get(
              json.dumps(edge["from"].get("key"), sort_keys=True)
          )
          target = operation_by_key.get(
              json.dumps(edge["to"].get("key"), sort_keys=True)
          )
          if source is None or target is None:
              continue
          if source[1]["method"] == "materialize" and target[1]["method"] == "update":
              configuration_service_pairs.append((source, target))
      assert len(configuration_service_pairs) == 1, configuration_service_pairs
      (publish_ordinal, publish), (reload_ordinal, reload) = configuration_service_pairs[0]
      assert publish["target"]["resource"]["key"].endswith("server-configuration"), publish
      assert reload["target"]["resource"]["key"].endswith("service"), reload

      diagnostic = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{failed_reload} {transaction}"
      ))
      publish_events = [
          event["kind"] for event in diagnostic["timeline"]["events"]
          if event.get("node_ordinal") == publish_ordinal
      ]
      reload_events = [
          event["kind"] for event in diagnostic["timeline"]["events"]
          if event.get("node_ordinal") == reload_ordinal
      ]
      assert "effect-completed" in publish_events, (publish_events, diagnostic)
      assert "effect-indeterminate" in reload_events, (reload_events, diagnostic)
      assert "effect-completed" not in reload_events, (reload_events, diagnostic)
      assert "settled-failure" in reload_events, (reload_events, diagnostic)
      terminal = json.loads(runtime.succeed(f"cat {transaction_root}/terminal.json"))
      assert terminal["terminal"] == "settled-failure", terminal
      assert_payloads_immutable()
      runtime.succeed(f"""
          rm /run/systemd/system/nginx.service.d/99-fail-reload.conf
          systemctl daemon-reload
          {APM} config discard
      """)

      # Restore the original declaration through the same reload path so the
      # retained generation used by the reboot and rollback checks below has
      # the fixture's canonical contents.
      write_file(
          "/run/runtime-module-fixtures/20-services-original.nix",
          services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-original.nix"
      )
      apply_worktree("/run/runtime-module-composition-reload-restore")
      configured = current_generation()
      assert configured != reloaded, (reloaded, configured)
      assert_package_configuration()
      assert runtime.succeed(
          "systemctl show -p InvocationID --value nginx.service"
      ).strip() == nginx_invocation
      assert runtime.succeed(
          "systemctl show -p MainPID --value nginx.service"
      ).strip() == nginx_pid
      assert_payloads_immutable()

      manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert manifest["schema"] == "aos.config-manifest/v2", manifest["schema"]
      runtime_input = manifest["inputs"]["runtime_modules"]
      assert runtime_input["schema"] == "aos.runtime-module-set/v1", runtime_input
      assert runtime_input["trust_mode"] == "local-root", runtime_input
      assert runtime_input["store_path"].startswith("/nix/store/"), runtime_input
      assert runtime_input["entrypoints"] == [
          "10-packages.nix",
          "20-services.nix",
      ], runtime_input
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "active runtime modules:" in status, status
      assert "(2 entrypoints," in status, status
      assert manifest["inputs"]["host_nix"]["store_path"].startswith(
          "/nix/store/"
      )
      assert manifest["inputs"]["host_nix"] == platform_host_input
      assert manifest["inputs"]["instance_facts"] == platform_facts_input
      assert runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0] == platform_hash

      # Select the production configuration publication from the checked plan,
      # then interrupt that exact operation after its external result. No test
      # catalog or copied provider identity participates in fault selection.
      baseline_state = activation_state(configured)
      publish_selector = selector_for(baseline_state["publish"][1])
      process_services_module = services_module.replace(
          'body = "nginx-runtime";',
          'body = "nginx-runtime-process-loss";',
      )
      write_file(
          "/run/runtime-module-fixtures/20-services-process-loss.nix",
          process_services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-process-loss.nix"
      )
      recovery_drop_in = disable_automatic_activation_recovery()
      arm_boundary("process-loss", publish_selector)
      start_apply(
          "runtime-module-process-loss.service",
          "/run/runtime-module-composition-process-loss",
      )

      held_process = held_boundary("process-loss", publish_selector)
      process_generation = current_generation()
      assert process_generation != configured, (configured, process_generation)
      process_state = activation_state(process_generation)
      assert held_process["event"]["transaction"] == process_state["transaction"]
      assert held_process["event"]["operation"]["plan"] == process_state["plan"]
      assert operation_matches_selector(
          process_state["publish"][1], publish_selector
      )
      process_handoff = retained_host_handoff(process_generation)
      process_journal_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(process_state['root'] + '/execution.journal')}"
      ).encode()
      runtime.succeed("grep -q 'nginx-runtime-process-loss' /etc/nginx/nginx.conf")
      assert runtime.succeed(
          f"{CURL} --fail --silent http://127.0.0.1:18080/health"
      ) == "nginx-runtime"

      process_diagnostic_before = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{process_generation} "
          f"{shlex.quote(process_state['transaction'])}"
      ))
      dependent_before = [
          event for event in process_diagnostic_before["timeline"]["events"]
          if event.get("node_ordinal") == process_state["dependent"][0]
      ]
      assert dependent_before == [], (dependent_before, process_diagnostic_before)

      kill_exact_activation_runtime()
      wait_apply("runtime-module-process-loss.service", False)
      runtime.wait_until_succeeds(
          f"{SYSTEMCTL} is-failed --quiet aos-activate.service", timeout=120
      )
      runtime.succeed(
          f"{FLOCK} --exclusive --nonblock /run/apm/switch.lock {COREUTILS}/true"
      )

      unresolved_generations = [configured, process_generation]
      inventory_before_gc = retained_path_inventory(unresolved_generations)
      retained_paths = retained_store_paths(
          unresolved_generations, process_state["root"]
      )
      clean_unresolved = json.loads(runtime.succeed(
          f"{APM} --json clean --system --generations --keep 1", timeout=600
      ))
      generations_after_clean = clean_unresolved["configuration"][
          "generations_after"
      ]
      assert configured in generations_after_clean, clean_unresolved
      assert process_generation in generations_after_clean, clean_unresolved
      runtime.succeed(f"{APM} gc", timeout=600)
      assert retained_path_inventory(unresolved_generations) == inventory_before_gc
      for path in retained_paths:
          runtime.succeed(f"test -e {shlex.quote(path)}")
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(process_state['root'] + '/plan-bundle.json')}"
      ).encode() == process_state["bundle_bytes"]
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(process_state['root'] + '/execution.journal')}"
      ).encode() == process_journal_before
      assert runtime.succeed(
          f"{CURL} --fail --silent http://127.0.0.1:18080/health"
      ) == "nginx-runtime"

      resume_activation_recovery(recovery_drop_in)
      resumed_process = resumed_boundary(
          "process-loss",
          publish_selector,
          process_state["transaction"],
          process_state["plan"],
      )
      process_diagnostic_reconciling = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{process_generation} "
          f"{shlex.quote(process_state['transaction'])}"
      ))
      dependent_reconciling = [
          event for event in process_diagnostic_reconciling["timeline"]["events"]
          if event.get("node_ordinal") == process_state["dependent"][0]
      ]
      assert dependent_reconciling == [], (
          dependent_reconciling, process_diagnostic_reconciling,
      )
      release_reconciliation("process-loss")
      runtime.wait_until_succeeds(
          f"{SYSTEMCTL} is-active --quiet aos-activate.service", timeout=600
      )
      assert current_generation() == process_generation
      assert_package_configuration("nginx-runtime-process-loss")
      assert retained_host_handoff(process_generation) == process_handoff

      process_diagnostic = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{process_generation} "
          f"{shlex.quote(process_state['transaction'])}"
      ))
      publish_timeline = [
          event for event in process_diagnostic["timeline"]["events"]
          if event.get("node_ordinal") == process_state["publish"][0]
      ]
      dependent_timeline = [
          event for event in process_diagnostic["timeline"]["events"]
          if event.get("node_ordinal") == process_state["dependent"][0]
      ]
      assert [
          event["kind"] for event in publish_timeline
          if event["kind"].startswith("reconciled-")
      ] == ["reconciled-completed"], publish_timeline
      assert [event["kind"] for event in dependent_timeline] == [
          "operation-admitted", "effect-started", "effect-completed",
      ], dependent_timeline
      assert publish_timeline[-1]["sequence"] < dependent_timeline[0]["sequence"]
      process_authority = current_authority(
          process_state["transaction"], process_state["plan"]
      )

      # Repeat the same checked production operation and remove power from the
      # guest. The retained disk must reopen the exact transaction under fresh
      # receiving authority before its dependent service reload can execute.
      power_services_module = services_module.replace(
          'body = "nginx-runtime";',
          'body = "nginx-runtime-power-loss";',
      )
      write_file(
          "/run/runtime-module-fixtures/20-services-power-loss.nix",
          power_services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-power-loss.nix"
      )
      arm_boundary("power-loss", publish_selector)
      start_apply(
          "runtime-module-power-loss.service",
          "/run/runtime-module-composition-power-loss",
      )

      held_power = held_boundary("power-loss", publish_selector)
      power_generation = current_generation()
      assert power_generation != process_generation, (
          process_generation, power_generation,
      )
      power_state = activation_state(power_generation)
      assert held_power["event"]["transaction"] == power_state["transaction"]
      assert held_power["event"]["operation"]["plan"] == power_state["plan"]
      assert operation_matches_selector(
          power_state["publish"][1], publish_selector
      )
      handoff_before_power_loss = retained_host_handoff(power_generation)
      authority_before_power_loss = current_authority(
          power_state["transaction"], power_state["plan"]
      )
      power_plan_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state['root'] + '/plan-bundle.json')}"
      ).encode()
      power_journal_before = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state['root'] + '/execution.journal')}"
      ).encode()
      runtime.succeed("grep -q 'nginx-runtime-power-loss' /etc/nginx/nginx.conf")
      assert runtime.succeed(
          f"{CURL} --fail --silent http://127.0.0.1:18080/health"
      ) == "nginx-runtime-process-loss"
      boot_id_before = runtime.succeed(
          f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
      ).strip()
      manager_id_before = runtime.succeed(
          f"{SYSTEMCTL} show init.scope -p InvocationID --value"
      ).strip()

      runtime.power_cycle(timeout=600)
      assert actual_boot_initrd_identity(expected_boot_initrd) == (
          boot_initrd_identity_before
      )
      boot_id_after = runtime.succeed(
          f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
      ).strip()
      manager_id_after = runtime.succeed(
          f"{SYSTEMCTL} show init.scope -p InvocationID --value"
      ).strip()
      assert boot_id_after != boot_id_before, (boot_id_before, boot_id_after)
      assert manager_id_after and manager_id_after != manager_id_before, (
          manager_id_before, manager_id_after,
      )
      assert retained_host_handoff(power_generation) == handoff_before_power_loss

      resumed_power = resumed_boundary(
          "power-loss",
          publish_selector,
          power_state["transaction"],
          power_state["plan"],
      )
      authority_after_power_loss = current_authority(
          power_state["transaction"], power_state["plan"]
      )
      assert_fresh_receiving_authority(
          authority_before_power_loss,
          authority_after_power_loss,
          power_state["plan"],
      )
      release_reconciliation("power-loss")
      runtime.wait_until_succeeds(
          f"{SYSTEMCTL} is-active --quiet aos-activate.service", timeout=600
      )
      assert current_generation() == power_generation
      assert_package_configuration("nginx-runtime-power-loss")
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state['root'] + '/plan-bundle.json')}"
      ).encode() == power_plan_before
      assert power_journal_before in runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state['root'] + '/execution.journal')}"
      ).encode()
      power_diagnostic = json.loads(runtime.succeed(
          f"{AOS} --json ability diagnostic "
          f"/var/lib/profiles/system/gen-{power_generation} "
          f"{shlex.quote(power_state['transaction'])}"
      ))
      power_publish_timeline = [
          event for event in power_diagnostic["timeline"]["events"]
          if event.get("node_ordinal") == power_state["publish"][0]
      ]
      assert [
          event["kind"] for event in power_publish_timeline
          if event["kind"].startswith("reconciled-")
      ] == ["reconciled-completed"], power_publish_timeline
      assert publish_timeline[-1]["sequence"] < power_publish_timeline[-1]["sequence"]
      assert process_authority["plan"] == process_state["plan"]
      assert resumed_process["event"]["transaction"] == process_state["transaction"]
      assert resumed_power["event"]["transaction"] == power_state["transaction"]

      clean_recovered = json.loads(runtime.succeed(
          f"{APM} --json clean --system --generations --keep 1", timeout=600
      ))
      assert power_generation in clean_recovered["configuration"][
          "generations_after"
      ], clean_recovered
      runtime.succeed(f"{APM} gc", timeout=600)
      assert current_generation() == power_generation
      assert retained_host_handoff(power_generation) == handoff_before_power_loss
      assert runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(power_state['root'] + '/plan-bundle.json')}"
      ).encode() == power_plan_before
      assert_package_configuration("nginx-runtime-power-loss")

      write_file(
          "/run/runtime-module-fixtures/20-services-recovery-restored.nix",
          services_module,
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/20-services-recovery-restored.nix"
      )
      apply_worktree("/run/runtime-module-composition-recovery-restore")
      configured = current_generation()
      assert configured != power_generation, (power_generation, configured)
      restored_manifest = read_json(
          f"/var/lib/profiles/system/gen-{configured}/manifest.json"
      )
      assert restored_manifest["inputs"]["runtime_modules"] == runtime_input
      assert_package_configuration()
      assert_payloads_immutable()

      # Ordinary switch porcelain defaults to the active retained runtime set,
      # rather than silently dropping supplemental modules. Inspect the new
      # no-op generation to prove all three input identities survive.
      previous_configured = configured
      runtime.succeed(
          f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} switch "
          "--eval-root /run/runtime-module-composition-no-op",
          timeout=600,
      )
      configured = current_generation()
      assert configured != previous_configured, (previous_configured, configured)
      switch_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert switch_manifest["inputs"]["runtime_modules"] == runtime_input
      assert switch_manifest["inputs"]["host_nix"] == platform_host_input
      assert switch_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert (
          switch_manifest["inputs"]["expected_current_generation"]
          == previous_configured
      )
      assert_package_configuration()
      assert_payloads_immutable()

      # A bad supplemental fragment must fail before activation and preserve
      # both the durable pointer and live package state.
      invalid_module = """{
        aos.apm.desiredPackages = [ "nginx" "envoy" "k3s-worker" ];
        aos.runtimeModules.thisOptionDoesNotExist = true;
      }
      """
      write_file(
          "/run/runtime-module-fixtures/invalid.nix", invalid_module
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/invalid.nix"
      )
      runtime.succeed(textwrap.dedent(f"""
          set -eu
          if XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config apply \\
            --eval-root /run/runtime-module-composition-invalid \\
            >/run/runtime-module-composition-invalid.out 2>&1; then
            echo 'invalid runtime module candidate unexpectedly succeeded' >&2
            exit 1
          fi
      """), timeout=600)
      assert current_generation() == configured
      assert_package_configuration()
      assert_payloads_immutable()
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed

      # Deliberately replace the mutable worktree with valid but hostile
      # content. Boot authority must remain the retained generation snapshot.
      dirty_module = """{
        environment.etc."runtime-modules/operator.conf".text = "DIRTY\\n";
        nginx.enable = false;
        envoy.enable = false;
      }
      """
      write_file(
          "/run/runtime-module-fixtures/dirty.nix", dirty_module
      )
      runtime.succeed(f"{APM} config replace 10-packages.nix /run/runtime-module-fixtures/dirty.nix")
      runtime.succeed(f"{APM} config remove 20-services.nix")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix"], listed
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "worktree: /var/lib/aos/config/modules.d (1 entrypoints)" in status, status

      runtime.reboot_without_metadata()
      wait_for_activation()
      rebooted = current_generation()
      assert rebooted != configured, (configured, rebooted)
      assert_package_configuration()
      assert_payloads_immutable()
      reboot_manifest = json.loads(runtime.succeed(
          "cat /run/aos/manifest.json"
      ))
      assert reboot_manifest["inputs"]["runtime_modules"] == runtime_input
      assert reboot_manifest["inputs"]["host_nix"] == platform_host_input
      assert reboot_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert reboot_manifest["inputs"]["expected_current_generation"] == configured
      configured = rebooted
      assert runtime.succeed(
          f"{SHA256SUM} /var/lib/aos-provisioning/current/host.nix"
      ).split()[0] == platform_hash
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed

      # Removing the final entrypoint is itself an ordinary compare-and-switch
      # candidate. It must durably record the absence of runtime input rather
      # than falling back to the previous retained set on the next boot.
      runtime.succeed(f"{APM} config remove 10-packages.nix")
      runtime.succeed(f"{APM} config remove 20-services.nix")
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      apply_worktree("/run/runtime-module-composition-clear")
      cleared = current_generation()
      assert cleared != configured, (configured, cleared)
      cleared_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{cleared}/manifest.json"
      ))
      cleared_runtime_input = cleared_manifest["inputs"]["runtime_modules"]
      assert cleared_runtime_input["schema"] == "aos.runtime-module-set/v1"
      assert cleared_runtime_input["trust_mode"] == "local-root"
      assert cleared_runtime_input["store_path"].startswith("/nix/store/")
      assert cleared_runtime_input["entrypoints"] == []
      assert cleared_manifest["inputs"]["expected_current_generation"] == configured
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert cleared_runtime_input["store_path"] in status, status
      assert "(0 entrypoints," in status, status
      assert "worktree: /var/lib/aos/config/modules.d (0 entrypoints)" in status, status
      runtime.fail("test -e /etc/runtime-modules/operator.conf")
      runtime.wait_until_succeeds(
          "! systemctl is-active --quiet nginx.service", timeout=120
      )
      runtime.wait_until_succeeds(
          "! systemctl is-active --quiet envoy.service", timeout=120
      )

      runtime.reboot_without_metadata()
      wait_for_activation()
      rebooted_cleared = current_generation()
      assert rebooted_cleared != cleared, (cleared, rebooted_cleared)
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert cleared_runtime_input["store_path"] in status, status
      assert "(0 entrypoints," in status, status
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      reboot_manifest = json.loads(runtime.succeed("cat /run/aos/manifest.json"))
      assert (
          reboot_manifest["inputs"]["runtime_modules"]
          == cleared_runtime_input
      )
      assert reboot_manifest["inputs"]["host_nix"] == platform_host_input
      assert reboot_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert reboot_manifest["inputs"]["expected_current_generation"] == cleared
      cleared = rebooted_cleared
      runtime.fail("test -e /etc/runtime-modules/operator.conf")
      runtime.fail("systemctl is-active --quiet nginx.service")
      runtime.fail("systemctl is-active --quiet envoy.service")
      assert runtime.succeed(
          f"{SHA256SUM} /var/lib/aos-provisioning/current/host.nix"
      ).split()[0] == platform_hash

      # Same-ABI rollback must reactivate the selected generation's immutable
      # runtime module set, not the currently empty authoring worktree or the
      # runtime descriptor from the generation being left behind.
      runtime.succeed(
          f"{APM} rollback --system --generation {configured}", timeout=600
      )
      assert current_generation() == configured
      rollback_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert rollback_manifest["inputs"]["runtime_modules"] == runtime_input
      assert rollback_manifest["inputs"]["host_nix"] == platform_host_input
      assert rollback_manifest["inputs"]["instance_facts"] == platform_facts_input
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "(2 entrypoints," in status, status
      assert "worktree: /var/lib/aos/config/modules.d (0 entrypoints)" in status, status
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      assert_package_configuration()
      assert_payloads_immutable()
    '';
}
