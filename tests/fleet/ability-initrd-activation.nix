##! Exercises interrupted native initrd activation and checked host receipt.
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

      aos.activation.stages.host.configuration = [
        (builtins.path {
          path = ./_host-observer-disabled.nix;
          name = "aos-initrd-host-observer-disabled.nix";
        })
      ];
      aos.activation.stages.initrd.configuration = [
        observer.source
        (builtins.path {
          path = ./_initrd-controller-recovery-policy.nix;
          name = "aos-initrd-controller-recovery-policy.nix";
        })
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
            ${lib.escapeShellArg (builtins.toJSON {
            action = "terminate-peer";
            boundary = "dispatch-returned";
            invocation_action = "apply";
            sequence = "initrd-first-effect";
          })} \
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
    }
  ];
  selectedInitrd = activatedSystem.config.system.build.initrdDeploymentBundle.nativeTransaction;
  initrdController =
    (builtins.head (builtins.filter
      (node: builtins.elem "boot-preparations.aos-ability-initrd-controller" node.identity)
      (builtins.attrValues selectedInitrd.graph.nodes))).input;
  observerOrderedBeforeController =
    builtins.elem observerUnit initrdController.dependencies.requires
    && builtins.elem observerUnit initrdController.dependencies.after
    && builtins.elem "initrd-fs.target" initrdController.dependencies.before;
  observerAvailableInInitrd =
    builtins.elem
    (builtins.toString observer.package)
    activatedSystem.config.aos.boot.initrd.runtimeRoots;
  checkedSystem =
    if !observerOrderedBeforeController
    then throw "initrd ability controller must require the interruption observer"
    else if !(builtins.elem "initrd" selectedInitrd.scope)
    then throw "initrd activation must retain its native stage identity"
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
      import hashlib
      import json
      import shlex

      AOS = "${pkgs.aos}/bin/aos"
      COREUTILS = "${pkgs.coreutils}/bin"
      PREPARATION = ${builtins.toJSON activatedSystem.config.aos.boot.preparationExecutable}
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      INITRD_STATE = ${builtins.toJSON activatedSystem.config.aos.boot.substrateServices.initrdStateDirectory}
      HOST_STATE = ${builtins.toJSON activatedSystem.config.aos.boot.substrateServices.hostStateDirectory}
      INTERRUPTION_STATE = ${builtins.toJSON interruptionStateRoot}

      def read_json(path):
          return json.loads(target.succeed(f"{COREUTILS}/cat {shlex.quote(path)}"))

      def inspect(state):
          view = json.loads(target.succeed(
              f"{AOS} ability journal {shlex.quote(state + '/effects.journal')} --format json"
          ))
          assert view["schema"] == "aos.activation.inspection", view
          assert view["liveStateVerified"] is False, view
          assert view["incompleteTailBytes"] == 0, view
          assert view["pending"] is None, view
          assert view["completed"] is not None, view
          assert view["records"][-1]["event"] == "commit", view
          return view

      target.wait_for_unit("aos-ability-host-receiver.service", timeout=180)
      target.wait_for_unit("aos-activate.service", timeout=300)
      target.succeed("systemctl is-active multi-user.target")

      held = read_json(f"{INTERRUPTION_STATE}/held-event.json")
      resumed = read_json(f"{INTERRUPTION_STATE}/resumed-event.json")
      assert held["sequence"] == "initrd-first-effect", held
      assert resumed["sequence"] == held["sequence"], resumed
      assert held["event"]["schema"] == "aos.activation.boundary", held
      assert held["event"]["boundary"] == "dispatch-returned", held
      assert resumed["event"]["boundary"] == "observation-returned", resumed
      for field in ("transaction", "effect", "revision", "action", "journal_sequence"):
          assert resumed["event"][field] == held["event"][field], (field, held, resumed)
      assert held["event"]["action"] == "apply", held

      events = [json.loads(line) for line in target.succeed(
          f"{COREUTILS}/cat {INTERRUPTION_STATE}/events.jsonl"
      ).splitlines()]
      selected = [event for event in events if all(
          event[field] == held["event"][field]
          for field in ("transaction", "effect", "revision", "action", "journal_sequence")
      )]
      assert [event["boundary"] for event in selected].count("dispatch-returned") == 1, selected
      assert "observation-returned" in [event["boundary"] for event in selected], selected

      # The production verifier reauthenticates immutable inputs and replays
      # durable completion state after switch-root; inspector output is not a
      # substitute for this receiving-stage check.
      for stage, state in (("initrd", INITRD_STATE), ("host", HOST_STATE)):
          bundle = f"/usr/lib/aos/{stage}/deployment"
          target.succeed(
              f"{PREPARATION} verify-deployment --input {bundle} "
              f"--state-directory {shlex.quote(state)} --nix-store {NIX_STORE}"
          )
          transaction = read_json(f"{bundle}/transaction.json")
          assert transaction["schema"] == "aos.package.transaction", transaction
          assert stage in transaction["scope"], transaction["scope"]
          admission_digest = target.succeed(f"{COREUTILS}/sha256sum {bundle}/admission.json").split()[0]
          expected_digest = target.succeed(f"{COREUTILS}/cat {bundle}/admission-sha256").strip()
          assert expected_digest == "sha256:" + admission_digest
          assert read_json(f"{bundle}/admission.json")["schema"] == "aos.package.admission"
          view = inspect(state)
          assert view["retainedOutputs"], view
          if stage == "initrd":
              dispatches = [record for record in view["records"]
                  if record["event"] == "finished" and record.get("dispatch")
                  and record["transaction"] == held["event"]["transaction"]
                  and record["dispatch"]["effect"] == held["event"]["effect"]
                  and record["dispatch"]["journalSequence"] == held["event"]["journal_sequence"]]
              assert len(dispatches) == 1, dispatches
    '';
}
