##! Production structured-ability A/B rollout and fallback acceptance.
{
  lib,
  mkSystem,
  pkgs,
  systems ? null,
  qualificationImage ? false,
}: let
  observerController = pkgs.writeTextFile {
    name = "aos-image-rollout-boundary-controller";
    destination = "/bin/aos-image-rollout-boundary-controller";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      ${builtins.readFile ./ability-boundary-observer.py}
    '';
  };
  observerConfiguration = ''{"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}'';
  observerService = {
    description = "AOS image rollout execution-boundary controller";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    before = ["aos-activate.service"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${observerController}/bin/aos-image-rollout-boundary-controller";
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
  observerHostModule = ''
    environment.etc."aos/ability-execution-observer.json" = {
      text = ${builtins.toJSON observerConfiguration};
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = {
      description = "AOS image rollout execution-boundary controller";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      before = [ "aos-activate.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-image-rollout-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
      };
    };
  '';
  imageLifecycle = import ./system-image-rollback.nix {
    inherit lib mkSystem pkgs systems;
    extraFixtureModules = [observerModule];
  };
  image = imageLifecycle.abilityRolloutFixture;
  rollout = import ./_image-rollout-runtime-reference.nix {
    inherit lib pkgs;
    guestTools = qualificationImage;
  };
  qualificationTestScript =
    rollout.testPrelude
    + # python
    ''
      IMAGE_STATE = "/var/lib/profiles/image/state.json"
      QUALIFICATION_HOST_BODY = ${builtins.toJSON rollout.qualificationSetupBody}


      def image_state():
          return json.loads(target.succeed(f"cat {IMAGE_STATE}"))


      def generation(state, number):
          matches = [entry for entry in state["generations"] if entry["number"] == number]
          assert len(matches) == 1, (number, state)
          return matches[0]


      def hold_boot_commit():
          target.succeed(textwrap.dedent("""
              set -eu
              mkdir -p /var/etc/systemd/system/aos-image-boot-commit.service.d
              cat > /var/etc/systemd/system/aos-image-boot-commit.service.d/90-qualification-rollout.conf <<'EOF'
              [Service]
              ExecCondition=${pkgs.bash}/bin/bash -c 'test ! -e /var/lib/aos-test/hold-rollout-commit || test -e /var/lib/aos-test/allow-rollout-commit'
              EOF
              mkdir -p /var/lib/aos-test
              touch /var/lib/aos-test/hold-rollout-commit
              ${pkgs.coreutils}/bin/sync
              systemctl daemon-reload
          """))


      def stage_candidate():
          old_boot = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          before = image_state()
          assert before["running"] == before["default"], before
          assert before.get("pending") is None, before
          assert before.get("active_rollout") is None, before

          runtime.stage_published_candidate()
          target.succeed(
              f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM} upgrade --system --yes",
              timeout=1800,
          )
          staged = image_state()
          candidate = generation(staged, staged["pending"])
          assert staged["running"] == before["running"], staged
          assert staged["default"] == before["default"], staged
          assert staged.get("active_rollout") is None, staged
          assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == old_boot
          target.fail("test -e /var/lib/profiles/image/.transition-intent.json")
          return candidate


      def rollout_request(candidate):
          state = image_state()
          predecessor = generation(state, state["running"])

          def identity(record):
              return {
                  "toplevel": record["toplevel"],
                  "uki": record.get("uki_source_path") or record["uki_path"],
                  "executor": record["native_executor_ref"],
                  "state_format": record["state_version"],
              }

          now = int(target.succeed("date +%s%3N").strip())
          return {
              "strategy": "single-host-ab-v1",
              "concurrency": 1,
              "predecessor": identity(predecessor),
              "candidate": identity(candidate),
              "retention_expires_at_millis": now + 600000,
          }


      def write_qualification_host(path, activation):
          activation_json = json.dumps(activation, separators=(",", ":"))
          module = (
              "{ lib, ... }: {\n"
              "  aos.apm.desiredPackages = [ \"ability-reference-image-rollout\" ];\n"
              "  aos.abilities.activationInput = builtins.fromJSON "
              + json.dumps(activation_json)
              + ";\n"
              + QUALIFICATION_HOST_BODY
              + "}\n"
          )
          encoded = base64.b64encode(module.encode()).decode()
          target.succeed(
              f"printf %s {shlex.quote(encoded)} | "
              f"{COREUTILS}/base64 -d > {shlex.quote(path)}"
          )


      def begin_rollout(request, label):
          activation = generate_rollout_activation(request, "desired", label)
          host = f"/var/lib/aos-test/{label}-host.nix"
          write_qualification_host(host, activation)
          old_boot = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          runtime.expect_published_image("candidate")
          command = (
              f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM} switch "
              f"--from {shlex.quote(host)} "
              f"--eval-root /run/ability-rollout-{label}"
          )
          try:
              target.succeed(command, timeout=1800)
          except Exception as error:
              print(f"{label} switch crossed reboot: {error}")
          target.wait_until_succeeds(
              "test \"$(cat /proc/sys/kernel/random/boot_id)\" != "
              + shlex.quote(old_boot),
              timeout=900,
          )
          runtime.assert_published_image("candidate")
          return activation


      def provider_state():
          path = target.succeed(
              "set -- /var/lib/profiles/image/ability-rollouts/*/state.json; "
              "test \"$#\" -eq 1; printf '%s\\n' \"$1\""
          ).strip()
          return path, json.loads(target.succeed(f"cat {shlex.quote(path)}"))


      def assert_health_observation(request, configured):
          line = target.succeed(
              f"{COREUTILS}/tail -n 1 /var/lib/aos-test/health-observations"
          ).rstrip("\n")
          boot_id, booted, observed_configured = line.split("\t")
          assert boot_id == target.succeed(
              "cat /proc/sys/kernel/random/boot_id"
          ).strip(), line
          assert booted == request["candidate"]["toplevel"], line
          assert observed_configured == configured, line
          assert configured != request["candidate"]["toplevel"], line


      def settled_transaction():
          config = json.loads(target.succeed("cat /var/lib/profiles/system/state.json"))
          current = config["current"]
          proof = json.loads(target.succeed(
              f"cat /var/lib/profiles/system/gen-{current}/activation.json"
          ))
          transaction = proof["native_ability_transaction"]
          root = (
              f"/var/lib/profiles/system/gen-{current}/ability-transactions/"
              f"{transaction}"
          )
          target.succeed(f"test -s {shlex.quote(root + '/execution.journal')}")
          terminal = json.loads(target.succeed(
              f"cat {shlex.quote(root + '/terminal.json')}"
          ))
          assert terminal["schema"] == "aos.ability.transaction-terminal/v1", terminal
          assert terminal["terminal"] == "succeeded", terminal
          return current, transaction


      def assert_retention_roots(request, state_path):
          root = state_path.rsplit("/", 1)[0]
          for name, identity in (
              ("predecessor-toplevel", request["predecessor"]),
              ("candidate-toplevel", request["candidate"]),
          ):
              observed = target.succeed(
                  f"{COREUTILS}/readlink {shlex.quote(root + '/' + name)}"
              ).strip()
              assert observed == identity["toplevel"], (name, observed, identity)
          target.succeed(
              "set -- /boot/EFI/.aos-rollout-retention/*.efi; test \"$#\" -eq 2"
          )


      def release_boot_commit():
          target.succeed(
              "touch /var/lib/aos-test/allow-rollout-commit && "
              "systemctl start aos-image-boot-commit.service",
              timeout=600,
          )
          target.wait_until_succeeds(
              "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
          )


      target = runtime
      hold_boot_commit()
      publish_rollout_package()
      candidate = stage_candidate()
      request = rollout_request(candidate)
      configured_before = target.succeed(
          f"{COREUTILS}/readlink -f /var/lib/profiles/system/current/toplevel"
      ).strip()

      if runtime.rollout_branch == "healthy":
          begin_rollout(request, "healthy")
          target.wait_until_succeeds(
              f"{JQ} -e '.active_rollout.status == \"candidate_booted\"' {IMAGE_STATE}",
              timeout=900,
          )
          state_path, provider = provider_state()
          target.wait_until_succeeds(
              f"{JQ} -e '.phase == \"healthy-retained\"' {shlex.quote(state_path)}",
              timeout=900,
          )
          provider = json.loads(target.succeed(f"cat {shlex.quote(state_path)}"))
          assert provider["outcome"] == "candidate-healthy", provider
          assert_health_observation(request, configured_before)
          settled_transaction()
          retained = image_state()
          assert retained.get("active_rollout") is not None, retained
          assert retained.get("last_rollout") is None, retained
          assert_retention_roots(request, state_path)
          release_boot_commit()
          committed = image_state()
          assert committed.get("active_rollout") is None, committed
          assert committed["last_rollout"]["status"] == "succeeded", committed

          deadline_seconds = request["retention_expires_at_millis"] // 1000 + 1
          target.succeed(f"date -s @{deadline_seconds}")
          retirement = generate_rollout_activation(request, "retire", "retire")
          retirement_host = "/var/lib/aos-test/retirement-host.nix"
          write_qualification_host(retirement_host, retirement)
          target.succeed(
              f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM} switch "
              f"--from {retirement_host} "
              "--eval-root /run/ability-rollout-retire",
              timeout=1200,
          )
          retired = json.loads(target.succeed(f"cat {shlex.quote(state_path)}"))
          assert retired["phase"] == "retired", retired
          root = state_path.rsplit("/", 1)[0]
          target.fail(f"test -e {shlex.quote(root + '/predecessor-toplevel')}")
          target.fail(f"test -e {shlex.quote(root + '/candidate-toplevel')}")
          target.succeed(
              "set -- /boot/EFI/.aos-rollout-retention/*.efi; "
              "test \"$1\" = '/boot/EFI/.aos-rollout-retention/*.efi'"
          )
          runtime.assert_published_image("candidate")
          ROLLOUT_BRANCH_EVIDENCE = {
              "branch": "healthy",
              "outcome": "candidate-healthy",
              "retired": True,
          }
      elif runtime.rollout_branch == "fallback":
          target.succeed("touch /var/lib/aos-test/rollout-health-fail")
          begin_rollout(request, "fallback")
          assert_health_observation(request, configured_before)
          candidate_boot = target.succeed(
              "cat /proc/sys/kernel/random/boot_id"
          ).strip()
          target.succeed("touch /var/lib/aos-test/allow-rollout-health-fail")
          runtime.expect_published_image("predecessor")
          target.wait_until_succeeds(
              "test \"$(cat /proc/sys/kernel/random/boot_id)\" != "
              + shlex.quote(candidate_boot),
              timeout=900,
          )
          runtime.assert_published_image("predecessor")
          state_path, provider = provider_state()
          target.wait_until_succeeds(
              f"{JQ} -e '.phase == \"fallback-retained\"' {shlex.quote(state_path)}",
              timeout=900,
          )
          provider = json.loads(target.succeed(f"cat {shlex.quote(state_path)}"))
          assert provider["outcome"] == "predecessor-fallback", provider
          settled_transaction()
          retained = image_state()
          assert retained.get("active_rollout") is not None, retained
          assert retained.get("last_rollout") is None, retained
          assert_retention_roots(request, state_path)
          release_boot_commit()
          failed = image_state()
          assert failed.get("active_rollout") is None, failed
          assert failed["last_rollout"]["status"] == "health_failed", failed
          ROLLOUT_BRANCH_EVIDENCE = {
              "branch": "fallback",
              "outcome": "predecessor-fallback",
              "retired": False,
          }
      else:
          raise RuntimeError(f"unknown rollout branch {runtime.rollout_branch!r}")
    '';
  baseTarget = imageLifecycle.machines.target;
  targetClosures = (baseTarget.extraClosures or []) ++ rollout.extraClosures;
  fallbackHost = ''
    {
      aos.provisioning.storage.partitions.var.sizeMin = "24G";
      aos.networking.hostName = "fallback";
      aos.networking.useDHCP = false;
      aos.networking.interfaces.eth0.address = "192.168.50.12/24";
      aos.apm.desiredPackages = [ "aos-test-agent" ];

      environment.etc."hosts".text = "127.0.0.1 localhost\n192.168.50.10 registry\n192.168.50.12 fallback\n";
    }
  '';
in {
  name = "ability-native-image-rollout";
  timeout = 7200;
  bootTimeout = 600;

  machines = {
    registry = imageLifecycle.machines.registry;
    healthy =
      baseTarget
      // {
        extraClosures = targetClosures;
      };
    fallback =
      baseTarget
      // {
        extraClosures = targetClosures;
        metadata = baseTarget.metadata // {"host.nix" = fallbackHost;};
      };
  };

  testScript =
    rollout.testPrelude
    + # python
    ''
      import re

      IMAGE_STATE = "/var/lib/profiles/image/state.json"
      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      BOUNDARY_ROOT = "/var/lib/aos/ability-boundary-test"
      CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
      EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
      HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
      RESUMED_EVENT = f"{BOUNDARY_ROOT}/resumed-event.json"
      TARGET = f"{BOUNDARY_ROOT}/target.json"
      OBSERVER_CONTROLLER = (
          "${observerController}/bin/aos-image-rollout-boundary-controller"
      )
      OBSERVER_HOST_MODULE = ${builtins.toJSON observerHostModule}
      HEALTH_OPERATION = "observe-health"


      def image_state():
          return json.loads(target.succeed(f"cat {IMAGE_STATE}"))


      def generation(state, number):
          matches = [entry for entry in state["generations"] if entry["number"] == number]
          assert len(matches) == 1, (number, state)
          return matches[0]


      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          return int(target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip())


      def write_canonical(path, value):
          payload = json.dumps(
              value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
          ).encode()
          target.succeed(
              f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} "
              f"{payload.hex()}"
          )


      def arm_health_boundary(sequence):
          target.succeed(
              f"${pkgs.coreutils}/bin/rm -f {shlex.quote(HELD_EVENT)} "
              f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
          )
          write_canonical(TARGET, {
              "boundary": "effect-returned",
              "operation_key": HEALTH_OPERATION,
              "purpose": "effect",
              "sequence": sequence,
          })


      def read_boundary(path):
          return json.loads(target.succeed(
              f"${pkgs.coreutils}/bin/cat {shlex.quote(path)}"
          ))


      def wait_for_health_boundary(path, sequence, purpose, boundary):
          target.wait_until_succeeds(
              f"test -s {shlex.quote(path)}", timeout=420
          )
          record = read_boundary(path)
          event = record["event"]
          assert record["sequence"] == sequence, record
          assert event["operation"]["operation"]["key"] == HEALTH_OPERATION, event
          assert event["purpose"] == purpose, event
          assert event["boundary"] == boundary, event
          return event


      def disable_automatic_activation_recovery():
          drop_in_directory = "/run/systemd/system/aos-activate.service.d"
          drop_in = f"{drop_in_directory}/90-image-rollout-power-loss.conf"
          target.succeed(textwrap.dedent(f"""
              set -eu
              ${pkgs.coreutils}/bin/mkdir -p {drop_in_directory}
              ${pkgs.coreutils}/bin/printf '%s\\n' '[Service]' 'Restart=no' \
                > {drop_in}
              systemctl daemon-reload
              test "$(systemctl show aos-activate.service -p Restart --value)" = no
          """))
          return drop_in


      def kill_candidate_activation_runtime(request):
          executable = (
              request["candidate"]["executor"]
              + "/bin/.aos-package-runtime-unwrapped"
          )
          killed = target.succeed(textwrap.dedent(f"""
              set -eu
              matches=""
              for candidate in /proc/[0-9]*/exe; do
                resolved=$(${pkgs.coreutils}/bin/readlink "$candidate" 2>/dev/null || true)
                [ "$resolved" = {shlex.quote(executable)} ] || continue
                process=''${{candidate#/proc/}}
                process=''${{process%/exe}}
                command=$(${pkgs.coreutils}/bin/tr '\\000' ' ' \
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
          target.wait_until_succeeds(
              "state=$(systemctl show aos-activate.service -p ActiveState --value); "
              "test \"$state\" = failed -o \"$state\" = inactive",
              timeout=120,
          )


      def resume_activation_recovery(drop_in):
          target.succeed(textwrap.dedent(f"""
              set -eu
              ${pkgs.coreutils}/bin/rm -f {shlex.quote(drop_in)}
              systemctl daemon-reload
              systemctl reset-failed aos-activate.service
              systemctl --no-block start aos-activate.service
          """))


      def health_boundary_events(transaction, plan):
          events = [
              json.loads(line)
              for line in target.succeed(
                  f"${pkgs.coreutils}/bin/cat {shlex.quote(EVENTS)}"
              ).splitlines()
              if line
          ]
          return [
              event for event in events
              if event["transaction"] == transaction
              and event["operation"]["plan"] == plan
              and event["operation"]["operation"]["key"] == HEALTH_OPERATION
          ]


      def rollout_store_paths(request):
          return sorted({
              identity[field]
              for identity in (request["predecessor"], request["candidate"])
              for field in ("toplevel", "executor")
          })


      def assert_paths_exist(paths):
          for path in paths:
              target.succeed(f"test -e {shlex.quote(path)}")


      def collect_unrooted_store_sentinel(label):
          source = f"/var/lib/aos-test/{label}-unrooted"
          return target.succeed(
              f"printf %s {shlex.quote(label)} > {shlex.quote(source)}; "
              f"NIX_REMOTE= ${pkgs.nix}/bin/nix-store --add-fixed sha256 "
              f"{shlex.quote(source)}"
          ).strip()


      def collect_garbage(sentinel, retained_paths):
          target.succeed(
              f"${pkgs.coreutils}/bin/rm -f /var/lib/aos-test/*-unrooted; "
              f"NIX_REMOTE= ${pkgs.nix}/bin/nix-store --gc",
              timeout=1200,
          )
          target.fail(f"test -e {shlex.quote(sentinel)}")
          assert_paths_exist(retained_paths)


      def bootstrap_target(machine):
          global target
          target = machine
          target.wait_until_succeeds(
              "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
          )
          target.wait_until_succeeds(
              "systemctl is-active --quiet multi-user.target", timeout=420
          )
          if efivar_byte("SetupMode") == 1:
              efi_update = (
                  "PATH=${pkgs.util-linux}/bin:$PATH "
                  "${pkgs.efitools}/bin/efi-updatevar"
              )
              keys = "${pkgs.secure-boot-test-keys}"
              for variable in ("db", "KEK", "PK"):
                  target.succeed(
                      f"{efi_update} -f {keys}/{variable}.auth {variable} 2>&1"
                  )
              target.reboot(timeout=600)
              target.wait_until_succeeds(
                  "systemctl is-active --quiet aos-image-boot-commit.service",
                  timeout=420,
              )
              target.wait_until_succeeds(
                  "systemctl is-active --quiet multi-user.target", timeout=420
              )
          assert efivar_byte("SecureBoot") == 1

          # Hold final boot commit after the native journal settles. This makes
          # the provider/journal-before-physical-commit boundary observable.
          target.succeed(textwrap.dedent("""
              set -eu
              mkdir -p /var/etc/systemd/system/aos-image-boot-commit.service.d
              cat > /var/etc/systemd/system/aos-image-boot-commit.service.d/90-ability-rollout.conf <<'EOF'
              [Service]
              ExecCondition=${pkgs.bash}/bin/bash -c 'test ! -e /var/lib/aos-test/hold-rollout-commit || test -e /var/lib/aos-test/allow-rollout-commit'
              EOF
              mkdir -p /var/lib/aos-test
              touch /var/lib/aos-test/hold-rollout-commit
              ${pkgs.coreutils}/bin/sync
              systemctl daemon-reload
          """))


      def publish_system_image():
          registry.wait_for_unit("aos-registry-server-gitd.service", timeout=180)
          registry.wait_until_succeeds(
              "systemctl is-active --quiet aos-pkg-test-static-cache-server.target",
              timeout=180,
          )
          registry.wait_until_succeeds(
              "systemctl is-active --quiet aos-nix-db.service", timeout=180
          )
          registry.succeed(textwrap.dedent("""
              set -eu
              export HOME=/tmp
              export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
              export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/nix-conf
              export PATH="${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
              mkdir -p "$NIX_CONF_DIR"
              printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' > "$NIX_CONF_DIR/nix.conf"

              ${pkgs.nix}/bin/nix-store --check-validity '${image.candidateTop}'
              ${pkgs.nix}/bin/nix-store --check-validity '${image.candidateImage}'
              ${pkgs.aos.apr}/bin/apr create sysreg
              REG_DIR=$HOME/.local/share/apm/registries/sysreg
              mkdir -p "$REG_DIR/sb-certs"
              cp ${pkgs.secure-boot-test-keys}/db.crt "$REG_DIR/sb-certs/db.pem"
              DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
              ORIGIN=/var/lib/aos-registry-server/registries/sysreg
              git init --bare --object-format=sha256 "$ORIGIN"
              git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
              git -C "$REG_DIR" remote add origin "$ORIGIN"
              set -- '${image.candidateUki}'/*.efi
              test "$#" -eq 1

              ${pkgs.aos.apr}/bin/apr --json publish '${image.candidateTop}' \
                --name aos \
                --version 9999.0.0-image-rollback \
                --description 'ability A/B rollout fixture' \
                --license MIT \
                --maintainer test \
                --sysroot \
                --image-payload '${image.candidateImage}' \
                --image-disk '${image.candidateImageDisk}' \
                --image-info '${image.candidateImageInfo}' --image-format raw \
                --image-uki "$1" \
                --no-ca \
                --registry sysreg \
                --no-commit > /tmp/publish.json
              echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
          """), timeout=1200)

          publication = json.loads(registry.succeed("cat /tmp/publish.json"))
          ukis = publication["images"][0]["ukis"]
          signers = sorted({entry["sb_signer_cert_sha256"] for entry in ukis})
          assert {entry["slot"] for entry in ukis} == {"a", "b"}, ukis
          for entry in ukis:
              assert re.fullmatch(r"[0-9a-f]{64}", entry["expected_pcr11"]), entry

          commands = "\n".join(
              f"{APR} sb-certs add aos-db-{index} --cert-sha256 {signer} "
              "--registry sysreg --no-commit"
              for index, signer in enumerate(signers)
          )
          registry.succeed(textwrap.dedent(f"""
              set -eu
              export HOME=/tmp
              export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
              export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/nix-conf
              REG_DIR=$HOME/.local/share/apm/registries/sysreg
              DEFAULT_BRANCH=$(cat /tmp/sysreg-branch)
              ORIGIN=/var/lib/aos-registry-server/registries/sysreg
              {commands}
              {APR} verify --registry sysreg
              {APR} cache generate \
                --registry sysreg \
                --output /var/lib/sysreg-cache \
                --cache-url http://registry:8000/sysreg-cache \
                --priority 46 \
                --no-commit
              chmod -R a+rX /var/lib/sysreg-cache
              git -C "$REG_DIR" add -A
              git -C "$REG_DIR" commit -m 'release: ability A/B rollout fixture'
              git -C "$REG_DIR" tag v1.0.0
              git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
              chown -R aos-gitd:aos-gitd "$ORIGIN"
          """), timeout=1800)
          return registry.succeed("cat /tmp/sysreg-branch").strip()


      def add_system_registry(branch):
          target.succeed(
              "HOME=/tmp USER=root PATH=${pkgs.nix}/bin:$PATH "
              f"{APM} registry --system add --no-verify "
              "git://registry:9418/sysreg --name sysreg --priority 500 "
              f"--branch {shlex.quote(branch)}",
              timeout=180,
          )


      def stage_candidate():
          old_boot = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          before = image_state()
          assert before["running"] == before["default"] == 1, before
          target.succeed(
              "HOME=/tmp PATH=${pkgs.nix}/bin:$PATH "
              f"{APM} upgrade --system --yes",
              timeout=1800,
          )
          staged = image_state()
          candidate = generation(staged, staged["pending"])
          assert staged["running"] == staged["default"] == 1, staged
          assert staged["pending"] == candidate["number"], staged
          assert staged.get("active_rollout") is None, staged
          assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == old_boot
          target.fail("test -e /var/lib/profiles/image/.transition-intent.json")
          return candidate


      def rollout_request(candidate):
          state = image_state()
          predecessor = generation(state, state["running"])

          def identity(record):
              return {
                  "toplevel": record["toplevel"],
                  "uki": record.get("uki_source_path") or record["uki_path"],
                  "executor": record["native_executor_ref"],
                  "state_format": record["state_version"],
              }

          now = int(target.succeed("date +%s%3N").strip())
          return {
              "strategy": "single-host-ab-v1",
              "concurrency": 1,
              "predecessor": identity(predecessor),
              "candidate": identity(candidate),
              "retention_expires_at_millis": now + 600000,
          }


      def host_module(address):
          return textwrap.dedent(f"""
            aos.networking.hostName = "{address.split('.')[-1]}";
            aos.networking.useDHCP = false;
            aos.networking.interfaces.eth0.address = "{address}/24";
            aos.apm.drainScript = "${image.drainScript}";
            aos.apm.healthScript = "${image.healthScript}";
            environment.etc."hosts".text = "127.0.0.1 localhost\\n192.168.50.10 registry\\n{address} target\\n";
          """) + OBSERVER_HOST_MODULE


      def begin_rollout(request, label, address):
          activation = generate_rollout_activation(request, "desired", label)
          host = f"/var/lib/aos-test/{label}-host.nix"
          write_rollout_host(host, activation, host_module(address))
          old_boot = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          command = (
              "HOME=/tmp PATH=${pkgs.nix}/bin:$PATH "
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/ability-rollout-{label}"
          )
          try:
              target.succeed(command, timeout=1800)
          except Exception as error:
              print(f"{label} switch crossed reboot: {error}")
          target.wait_until_succeeds(
              "test \"$(cat /proc/sys/kernel/random/boot_id)\" != "
              + shlex.quote(old_boot),
              timeout=900,
          )
          return activation


      def provider_state():
          paths = target.succeed(
              "${pkgs.findutils}/bin/find /var/lib/profiles/image/ability-rollouts "
              "-mindepth 2 -maxdepth 2 -name state.json -type f -print"
          ).splitlines()
          assert len(paths) == 1, paths
          return paths[0], json.loads(target.succeed(f"cat {shlex.quote(paths[0])}"))


      def last_health_observation():
          line = target.succeed(
              "${pkgs.coreutils}/bin/tail -n 1 "
              "/var/lib/aos-test/health-observations"
          ).rstrip("\n")
          kind, boot_id, booted, configured = line.split("\t")
          return {
              "kind": kind,
              "boot_id": boot_id,
              "booted": booted,
              "configured": configured,
          }


      def assert_health_observation(kind, request, configured):
          observation = last_health_observation()
          expected_booted = request[
              "candidate" if kind == "candidate" else "predecessor"
          ]["toplevel"]
          assert observation["kind"] == kind, observation
          assert observation["booted"] == expected_booted, observation
          assert observation["configured"] == configured, observation
          if kind == "candidate":
              assert configured != request["candidate"]["toplevel"], observation
          return observation


      def settled_transaction():
          config = json.loads(target.succeed("cat /var/lib/profiles/system/state.json"))
          current = config["current"]
          proof = json.loads(target.succeed(
              f"cat /var/lib/profiles/system/gen-{current}/activation.json"
          ))
          transaction = proof["native_ability_transaction"]
          root = (
              f"/var/lib/profiles/system/gen-{current}/ability-transactions/"
              f"{transaction}"
          )
          target.succeed(f"test -s {shlex.quote(root + '/execution.journal')}")
          target.succeed(
              f"{JQ} -e '.schema == \"aos.ability.transaction-terminal/v1\" "
              "and .terminal == \"succeeded\"' "
              f"{shlex.quote(root + '/terminal.json')}"
          )
          return current, transaction


      def pending_transaction():
          config = json.loads(target.succeed("cat /var/lib/profiles/system/state.json"))
          current = config["current"]
          proof_path = f"/var/lib/profiles/system/gen-{current}/activation.json"
          target.wait_until_succeeds(
              f"{JQ} -e '.status == \"native-pending\" "
              "and (.native_ability_transaction | type == \"string\" and length > 0)' "
              f"{shlex.quote(proof_path)}",
              timeout=420,
          )
          proof = json.loads(target.succeed(f"cat {shlex.quote(proof_path)}"))
          transaction = proof["native_ability_transaction"]
          root = (
              f"/var/lib/profiles/system/gen-{current}/ability-transactions/"
              f"{transaction}"
          )
          target.succeed(f"test -s {shlex.quote(root + '/execution.journal')}")
          target.fail(f"test -e {shlex.quote(root + '/terminal.json')}")
          return current, transaction, root


      def release_boot_commit():
          target.succeed(
              "touch /var/lib/aos-test/allow-rollout-commit && "
              "systemctl start aos-image-boot-commit.service",
              timeout=600,
          )
          target.wait_until_succeeds(
              "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
          )


      publish_system_image()
      branch = registry.succeed("cat /tmp/sysreg-branch").strip()

      # Healthy candidate: advisory staging must not select or reboot. The
      # ordinary ability transaction consumes that exact pending generation.
      bootstrap_target(healthy)
      add_system_registry(branch)
      publish_rollout_package()
      candidate = stage_candidate()
      request = rollout_request(candidate)
      configured_before = target.succeed(
          "${pkgs.coreutils}/bin/readlink -f "
          "/var/lib/profiles/system/current/toplevel"
      ).strip()
      assert target.succeed("${pkgs.coreutils}/bin/readlink /run/current-system/health").strip() == "${image.predecessorHealthScript}"
      target.fail("/run/current-system/sw/bin/aos-rollout-health")
      assert_health_observation("predecessor", request, configured_before)
      arm_health_boundary("healthy-candidate")
      begin_rollout(request, "healthy", "192.168.50.11")
      target.wait_until_succeeds(
          f"{JQ} -e '.active_rollout.status == \"candidate_booted\"' {IMAGE_STATE}",
          timeout=900,
      )
      held = wait_for_health_boundary(
          HELD_EVENT, "healthy-candidate", "effect", "effect-returned"
      )
      state_path, provider = provider_state()
      assert provider["phase"] == "candidate-booted", provider
      assert provider["outcome"] == "candidate-healthy", provider
      assert_health_observation("candidate", request, configured_before)
      health_observations_before_recovery = int(target.succeed(
          "wc -l < /var/lib/aos-test/health-observations"
      ).strip())
      pending_generation, pending_id, pending_root = pending_transaction()
      assert held["transaction"] == pending_id, (held, pending_id)
      pending_plan = held["operation"]["plan"]

      drop_in = disable_automatic_activation_recovery()
      kill_candidate_activation_runtime(request)
      target.fail(f"test -e {shlex.quote(pending_root + '/terminal.json')}")

      retained_paths = rollout_store_paths(request)
      assert_paths_exist(retained_paths)
      rollout_root = state_path.rsplit("/", 1)[0]
      for name, identity in (
          ("predecessor-toplevel", request["predecessor"]),
          ("candidate-toplevel", request["candidate"]),
      ):
          path = f"{rollout_root}/{name}"
          assert target.succeed(
              f"${pkgs.coreutils}/bin/readlink {shlex.quote(path)}"
          ).strip() == identity["toplevel"]
      retained_ukis = target.succeed(
          "${pkgs.findutils}/bin/find /boot/EFI/.aos-rollout-retention "
          "-type f -name '*.efi' -print | ${pkgs.coreutils}/bin/sort"
      ).splitlines()
      assert len(retained_ukis) == 2, retained_ukis

      sentinel = collect_unrooted_store_sentinel("rollout-in-flight")
      target.succeed(f"test -e {shlex.quote(sentinel)}")
      collect_garbage(sentinel, retained_paths)
      assert target.succeed(
          "${pkgs.findutils}/bin/find /boot/EFI/.aos-rollout-retention "
          "-type f -name '*.efi' -print | ${pkgs.coreutils}/bin/sort"
      ).splitlines() == retained_ukis
      target.succeed(f"test -s {shlex.quote(pending_root + '/execution.journal')}")
      target.fail(f"test -e {shlex.quote(pending_root + '/terminal.json')}")

      resume_activation_recovery(drop_in)
      resumed = wait_for_health_boundary(
          RESUMED_EVENT,
          "healthy-candidate",
          "reconcile",
          "reconciliation-returned",
      )
      assert resumed["transaction"] == pending_id, (resumed, pending_id)
      assert resumed["operation"]["plan"] == pending_plan, (resumed, pending_plan)
      assert int(target.succeed(
          "wc -l < /var/lib/aos-test/health-observations"
      ).strip()) == health_observations_before_recovery
      write_canonical(CONTINUE, {"sequence": "healthy-candidate"})

      target.wait_until_succeeds(
          f"{JQ} -e '.phase == \"healthy-retained\"' {shlex.quote(state_path)}",
          timeout=420,
      )
      _, provider = provider_state()
      assert provider["phase"] == "healthy-retained", provider
      assert provider["outcome"] == "candidate-healthy", provider
      assert_health_observation("candidate", request, configured_before)
      assert int(target.succeed(
          "wc -l < /var/lib/aos-test/health-observations"
      ).strip()) == health_observations_before_recovery
      observed = health_boundary_events(pending_id, pending_plan)
      assert len([
          event for event in observed
          if event["purpose"] == "effect"
          and event["boundary"] == "effect-returned"
      ]) == 1, observed
      assert len([
          event for event in observed
          if event["purpose"] == "reconcile"
          and event["boundary"] == "reconciliation-returned"
      ]) == 1, observed
      assert target.succeed("${pkgs.coreutils}/bin/readlink /run/current-system").strip() == request["candidate"]["toplevel"]
      assert target.succeed("${pkgs.coreutils}/bin/readlink /run/current-system/health").strip() == "${image.healthScript}"
      settled_generation, settled_id = settled_transaction()
      assert (settled_generation, settled_id) == (
          pending_generation,
          pending_id,
      )
      before_commit = image_state()
      assert before_commit["running"] == candidate["number"], before_commit
      assert before_commit.get("active_rollout") is not None, before_commit
      assert before_commit.get("last_rollout") is None, before_commit
      target.succeed("test -L " + shlex.quote(state_path.rsplit("/", 1)[0] + "/candidate-toplevel"))
      target.succeed(
          "test \"$(${pkgs.findutils}/bin/find /boot/EFI/.aos-rollout-retention "
          "-type f -name '*.efi' | wc -l)\" -eq 2"
      )
      release_boot_commit()
      committed = image_state()
      assert committed.get("active_rollout") is None, committed
      assert committed["last_rollout"]["status"] == "succeeded", committed

      # Expiry authorizes a separate retirement transition. Physical terminal
      # state remains the authority; only rollout-specific roots disappear.
      deadline_seconds = request["retention_expires_at_millis"] // 1000 + 1
      target.succeed(f"date -s @{deadline_seconds}")
      retirement = generate_rollout_activation(request, "retire", "retire")
      retirement_host = "/var/lib/aos-test/retirement-host.nix"
      write_rollout_host(retirement_host, retirement, host_module("192.168.50.11"))
      target.succeed(
          f"HOME=/tmp PATH=${pkgs.nix}/bin:$PATH {APM} switch "
          f"--from {retirement_host} --eval-root /run/ability-rollout-retire",
          timeout=1200,
      )
      retired = json.loads(target.succeed(f"cat {shlex.quote(state_path)}"))
      assert retired["phase"] == "retired", retired
      for name in ("predecessor-toplevel", "candidate-toplevel"):
          target.fail(f"test -e {shlex.quote(rollout_root + '/' + name)}")
      assert target.succeed(
          "${pkgs.findutils}/bin/find /boot/EFI/.aos-rollout-retention "
          "-type f -name '*.efi' -print"
      ).splitlines() == []

      active = image_state()
      active_generation = generation(active, active["running"])
      assert active["running"] == active["default"] == candidate["number"], active
      assert active_generation["toplevel"] == request["candidate"]["toplevel"]
      assert active_generation["native_executor_ref"] == request["candidate"]["executor"]
      assert (
          active_generation.get("uki_source_path") or active_generation["uki_path"]
      ) == request["candidate"]["uki"]
      active_paths = sorted({
          request["candidate"]["toplevel"],
          request["candidate"]["executor"],
          f"/boot/{active_generation['uki_path']}",
      })
      assert_paths_exist(active_paths)
      target.succeed(
          f"test \"$(${pkgs.coreutils}/bin/readlink "
          f"/var/lib/profiles/image/image-gen-{candidate['number']}/toplevel)\" "
          f"= {shlex.quote(request['candidate']['toplevel'])}"
      )

      sentinel = collect_unrooted_store_sentinel("rollout-retired")
      collect_garbage(sentinel, active_paths)
      assert target.succeed(
          "${pkgs.coreutils}/bin/readlink /run/current-system"
      ).strip() == request["candidate"]["toplevel"]

      healthy.shutdown()

      # Failed candidate: provider failure is durable before reboot, and the
      # transaction settles only after the predecessor is running and held.
      bootstrap_target(fallback)
      add_system_registry(branch)
      publish_rollout_package()
      candidate = stage_candidate()
      request = rollout_request(candidate)
      configured_before = target.succeed(
          "${pkgs.coreutils}/bin/readlink -f "
          "/var/lib/profiles/system/current/toplevel"
      ).strip()
      target.succeed("touch /var/lib/aos-test/rollout-health-fail")
      assert target.succeed("${pkgs.coreutils}/bin/readlink /run/current-system/health").strip() == "${image.predecessorHealthScript}"
      target.succeed("/run/current-system/sw/bin/aos-rollout-health")
      assert_health_observation("predecessor", request, configured_before)
      begin_rollout(request, "fallback", "192.168.50.12")
      target.wait_until_succeeds(
          f"{JQ} -e '.running == 1 and .active_rollout.status == \"health_failed\"' {IMAGE_STATE}",
          timeout=1800,
      )
      _, provider = provider_state()
      assert provider["phase"] == "fallback-retained", provider
      assert provider["outcome"] == "predecessor-fallback", provider
      assert_health_observation("candidate", request, configured_before)
      settled_transaction()
      before_commit = image_state()
      assert before_commit.get("last_rollout") is None, before_commit
      release_boot_commit()
      failed = image_state()
      assert failed["running"] == failed["default"] == 1, failed
      assert failed.get("active_rollout") is None, failed
      assert failed["last_rollout"]["status"] == "health_failed", failed
      target.succeed("test \"$(wc -l < /var/lib/aos-test/health-boot-ids)\" -ge 1")
    '';

  qualification = lib.optionalAttrs qualificationImage {
    inherit qualificationTestScript;
    testScript = qualificationTestScript;
    stagingHubUrl = "https://aos.staging.andyl.org";
    inherit (rollout) extraClosures qualificationSetupBody;
    setupBody = rollout.qualificationSetupBody;
    candidateRuntimeCompanions = rollout.qualificationCandidateRuntimeCompanions;
  };
}
