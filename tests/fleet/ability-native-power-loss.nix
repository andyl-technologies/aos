##! Checks native operator recovery across an actual unclean QEMU power cut.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
  forwardObserverToCrucible ? false,
  extraRuntimeModules ? [],
  extraHostModule ? "",
  additionalClosures ? [],
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
  observer = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
    forwardToCrucible = forwardObserverToCrucible;
  };
  source = builtins.path {
    path = ./_native-reference-filesystem-configuration.nix;
    name = "native-power-loss-source.nix";
  };
  referenceSource = builtins.path {
    path = ./_reference-native-configuration.nix;
    name = "native-power-reference.nix";
  };
  observerSource = builtins.toFile "native-power-observer.nix" ''
    { ... }: { ${observer.hostModule} }
  '';
  runtimeSystem = mkSystem (fixture.runtimeModules
    ++ [observer.module]
    ++ extraRuntimeModules
    ++ [
      {
        aos.activation.stages.host.configuration = [referenceSource source observerSource];
      }
    ]);
in {
  name = "ability-native-power-loss";
  timeout = 3600;
  bootTimeout = 600;
  machines.runtime = {
    system = runtimeSystem;
    # The authenticated bundle retains the exact stage source roots; fleet
    # closure inputs remain packages rather than raw source paths.
    extraClosures = fixture.extraClosures ++ additionalClosures ++ [runtimeSystem.config.system.build.hostDeploymentBundle];
    varSizeMiB = 16384;
    memoryMiB = 4096;
  };
  # This physical recovery check is separate from domain matrix qualification.
  # Its journal and substrate facts do not substitute for other scenarios.
  testScript =
    fixture.testPrelude
    + ''
      import sys
      import types
      from pathlib import Path

      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      OBSERVER_CONTROLLER = "${observer.controller}/bin/aos-ability-boundary-controller"
      OBSERVER_HOST_MODULE = ${builtins.toJSON (observer.hostModule + extraHostModule)}
      NATIVE_EVIDENCE = types.ModuleType("native_activation_evidence")
      sys.modules[NATIVE_EVIDENCE.__name__] = NATIVE_EVIDENCE
      exec(compile(${builtins.toJSON (builtins.readFile ./native-activation-evidence.py)},
          "native-activation-evidence.py", "exec"), NATIVE_EVIDENCE.__dict__)
      FLIGHT = types.ModuleType("native_activation_flight")
      sys.modules[FLIGHT.__name__] = FLIGHT
      FLIGHT.__dict__.update({key: value for key, value in globals().items() if not key.startswith("__")})
      exec(compile(${builtins.toJSON (builtins.readFile ./native-activation-flight.py)},
          "native-activation-flight.py", "exec"), FLIGHT.__dict__)

      runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet multi-user.target", timeout=600)
      selected_path = "/var/lib/aos/native-domain-qualification-file"
      foreign_path = "/var/lib/aos/native-power-loss-foreign"
      runtime.succeed(f"printf 'foreign-stable\\n' > {foreign_path}")
      foreign_before = runtime.succeed(f"{COREUTILS}/stat -c '%d:%i:%u:%g:%a' {foreign_path}; {COREUTILS}/sha256sum {foreign_path}")

      worktree = write_reference_worktree(
          "/var/lib/aos/native-power-loss-operator",
          {"aos": {"nativeDomainQualification": {"content": "power-loss-native\n"}}},
          OBSERVER_HOST_MODULE,
      )
      original_graph = current_reference_graph()
      selected = [(effect, node) for effect, node in original_graph["nodes"].items()
                  if node["identity"][-3:] == ["configuration", "file", "native-qualification"]]
      assert len(selected) == 1, selected
      effect, original_node = selected[0]
      flight = FLIGHT.NativeFlight({"action": "apply"}, effect, worktree, "native-power-loss.service")
      FLIGHT.select(flight, "dispatch-returned", "native-physical-power-loss", "pause")
      FLIGHT.start(flight)
      held = FLIGHT.wait_held(flight, "native-physical-power-loss", "dispatch-returned")
      before = FLIGHT.inspect()
      assert before["pending"] is not None, before
      assert before["desired"] is not None, before
      selected_before = runtime.succeed(f"{COREUTILS}/stat -c '%d:%i:%u:%g:%a' {selected_path}; {COREUTILS}/sha256sum {selected_path}")
      assert runtime.succeed(f"{COREUTILS}/cat {selected_path}") == "power-loss-native\n"
      # Remove only the future selector. The already held invocation remains
      # unacknowledged until QEMU loses power; no graceful manager exit occurs.
      runtime.succeed(f"{COREUTILS}/rm -f {FLIGHT.TARGET}")
      runtime.power_cycle(timeout=600)
      runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet multi-user.target", timeout=1200)
      after = FLIGHT.inspect()
      assert after["incompleteTailBytes"] == 0, after
      assert after["pending"] is None, after
      assert after["records"][:len(before["records"])] == before["records"], (before, after)
      assert any(record["event"] == "commit" and record["transaction"] == held["transaction"]
               for record in after["records"]), after
      assert runtime.succeed(f"{COREUTILS}/stat -c '%d:%i:%u:%g:%a' {selected_path}; {COREUTILS}/sha256sum {selected_path}") == selected_before
      assert runtime.succeed(f"{COREUTILS}/stat -c '%d:%i:%u:%g:%a' {foreign_path}; {COREUTILS}/sha256sum {foreign_path}") == foreign_before

      events = [json.loads(line) for line in FLIGHT.read_bounded(FLIGHT.EVENTS).splitlines()]
      matching = [event for event in events if NATIVE_EVIDENCE.event_identity(event) == NATIVE_EVIDENCE.event_identity(held)]
      assert sum(event["boundary"] == "dispatch-started" for event in matching) == 1, matching
      assert any(event["boundary"] == "observation-returned" for event in matching), matching
      assert any(event["boundary"] == "outcome-durable" for event in matching), matching
      desired = current_reference_graph()
      assert desired == before["desired"], desired
      # The committed descriptor retains the ordinary admitted operator snapshot.
      evaluation = json.loads(runtime.succeed(f"{COREUTILS}/cat {PROFILE}/current/evaluation.json"))
      assert evaluation["runtimeConfiguration"], evaluation
      for authored in evaluation["runtimeConfiguration"]:
          assert authored.startswith("/nix/store/"), authored
          runtime.succeed(f"test -r {shlex.quote(authored)}")
      print("native power recovery retained exact intent, source, output, and foreign state")
    '';
}
