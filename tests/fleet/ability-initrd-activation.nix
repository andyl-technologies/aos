# Checked initrd-stage execution and host receipt qualification.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  observer = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
    external = true;
  };
  interruptionStateRoot = "/run/aos-initrd-interruption";
  observerUnit = "aos-ability-initrd-interruption-observer.service";
  activatedSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.image.erofsCompressionLevel = 1;
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };
      aos.packages.aos-ability-boundary-observer = {
        package = observer.package;
        bundle = true;
      };
      aos.boot.initrd.packageRoots = [observer.package];

      aos.abilities.stages.host.modules = [
        {aos.tests.executionObserver.enable = false;}
      ];
      aos.abilities.stages.initrd.modules = [
        observer.stageSettings
        {
          # Restart the same durable transaction after the observer kills its runner.
          aos.services."boot-preparations.aos-ability-initrd-controller".lifecycle.restart =
            lib.mkForce "on-failure";
        }
      ];

      # This test endpoint must be live before the ability graph it observes runs.
      boot.initrd.systemd.services.aos-ability-initrd-interruption-observer = {
        description = "Interrupt one returned initrd ability effect";
        requiredBy = ["aos-ability-initrd-controller.service"];
        before = ["aos-ability-initrd-controller.service"];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "exec";
          Restart = "on-failure";
        };
        script = ''
          mkdir -p -m 0700 ${interruptionStateRoot}
          printf '%s' \
            '{"action":"terminate-peer","boundary":"effect-returned","purpose":"effect","sequence":"initrd-first-effect"}' \
            > ${interruptionStateRoot}/target.json
          exec ${observer.controller}/bin/aos-ability-boundary-controller \
            --state-root ${interruptionStateRoot} \
            serve --socket ${observer.settings.socketPath}
        '';
        postStart = ''
          attempt=0
          while [ "$attempt" -lt 300 ]; do
            test -S ${observer.settings.socketPath} && exit 0
            sleep 0.1
            attempt=$((attempt + 1))
          done
          exit 1
        '';
      };
      boot.initrd.systemd.services.aos-ability-initrd-controller = {
        requires = [observerUnit];
        after = [observerUnit];
      };
    }
  ];
  initrdController =
    activatedSystem.config.boot.initrd.systemd.services.aos-ability-initrd-controller;
  selectedObserver =
    activatedSystem.config.system.build.initrdAbilityGraph.resolvedExecutionObserver;
  observerOrderedBeforeController =
    builtins.elem observerUnit initrdController.requires
    && builtins.elem observerUnit initrdController.after;
  observerAvailableInInitrd =
    builtins.elem
    (builtins.toString observer.package)
    activatedSystem.config.aos.boot.initrd.runtimeRoots;
  checkedSystem =
    if !observerOrderedBeforeController
    then throw "initrd ability controller must require the interruption observer"
    else if selectedObserver.socket != observer.settings.socketPath
    then throw "initrd ability fixed point selected another observer socket"
    else if !observerAvailableInInitrd
    then throw "initrd observer package is absent from the runtime roots"
    else activatedSystem;
in {
  name = "ability-initrd-activation";
  timeout = 600;
  bootTimeout = 300;

  machines.target = {
    system = checkedSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
  };

  testScript =
    # python
    ''
      import json


      target.wait_for_unit("aos-ability-host-receiver.service", timeout=120)
      target.succeed("systemctl is-active aos-ability-host-receiver.service")
      target.succeed("systemctl is-active multi-user.target")

      interruption_state = ${builtins.toJSON interruptionStateRoot}
      held = json.loads(target.succeed(
          f"cat {interruption_state}/held-event.json"
      ))
      resumed = json.loads(target.succeed(
          f"cat {interruption_state}/resumed-event.json"
      ))
      assert held["sequence"] == "initrd-first-effect", held
      assert held["event"]["boundary"] == "effect-returned", held
      assert held["event"]["purpose"] == "effect", held
      assert resumed["event"]["boundary"] == "reconciliation-returned", resumed
      assert resumed["event"]["purpose"] == "reconcile", resumed
      assert resumed["event"]["operation"] == held["event"]["operation"], resumed
      assert resumed["event"]["transaction"] == held["event"]["transaction"], resumed
      assert resumed["sequence"] == held["sequence"], resumed

      observer_events = [json.loads(line) for line in target.succeed(
          f"cat {interruption_state}/events.jsonl"
      ).splitlines()]
      selected_effect_returns = [
          event for event in observer_events
          if event["operation"] == held["event"]["operation"]
          and event["boundary"] == "effect-returned"
      ]
      assert len(selected_effect_returns) == 1, selected_effect_returns

      checkpoint_path = "/run/aos/ability-stage-handoff/initrd.json"
      checkpoint = json.loads(target.succeed(f"cat {checkpoint_path}"))
      assert checkpoint["schema"] == (
          "aos.ability.stage-handoff-checkpoint/v1"
      ), checkpoint
      assert checkpoint["source_stage"] == "initrd", checkpoint
      assert checkpoint["receiver_stage"] == "host", checkpoint
      assert checkpoint["source_stage_bundle_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["execution_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["status"] == "ownership-released", checkpoint
      assert checkpoint["transaction_root"] == (
          "/run/aos-boot-transaction-storage/aos/initrd-stage-journal"
      ), checkpoint
      transaction_storage = checkpoint["transaction_storage"]
      assert transaction_storage["interface"]["name"] == (
          "aos.boot.transaction-storage-view"
      ), transaction_storage
      assert transaction_storage["operations"] == ["observe"], transaction_storage
      assert transaction_storage["lifetime"] == "transaction", transaction_storage

      boot_id = target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip()
      boot_token = boot_id.replace("-", "")
      transaction = f"initrd-{boot_token}"
      journal_path = (
          "/var/lib/profiles/image/ability-stage-transactions/initrd/"
          f"{transaction}/execution.journal"
      )
      admission_path = (
          "/var/lib/profiles/image/ability-stage-transactions/initrd/"
          f"{transaction}/source-admission.json"
      )
      admission = json.loads(target.succeed(f"cat {admission_path}"))
      assert admission["schema"] == (
          "aos.ability.source-stage-admission-evidence/v1"
      ), admission
      admission_sha256 = target.succeed(
          f"sha256sum {admission_path}"
      ).split()[0]
      assert checkpoint["source_stage_admission_sha256"] == (
          "sha256:" + admission_sha256
      ), checkpoint

      requests = admission["requests"]
      responses = admission["responses"]
      assert requests and len(requests) == len(responses), admission
      for request, response in zip(requests, responses):
          assert request["boot_id"] == boot_id, request
          assert response["boot_id"] == boot_id, response
          assert response["challenge"] == request["challenge"]
          assert response["provider"] == request["provider"]
          assert response["interface"] == request["interface"]
          assert response["implementation"] == request["implementation"]
          assert response["state"] == "available", response
          assert response["incarnation"] is not None, response

      journal_hex = target.succeed(
          f"od -An -v -tx1 {journal_path}"
      ).replace(" ", "").replace("\n", "")
      for marker in (
          '"event":"source-completed"',
          '"terminal":"succeeded"',
          '"retained_resources"',
          '"name":"aos.boot.transaction-storage-view"',
          '"output":"retained-resource"',
          '"event":"host-received"',
      ):
          assert marker.encode().hex() in journal_hex, marker
    '';
}
