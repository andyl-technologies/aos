##! Production provider-state flights inside the foreground OCI runtime.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-foreground-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    effectQualification = true;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-state-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-provider-state-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-state-foreground";
    qualifiedCells = cells.groups.foreground;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()


      def foreground_activation(label, lifecycle, response):
          output = f"/var/lib/aos/provider-state-test/activation-{label}"
          authority = f"/var/lib/aos/provider-state-test/authority-{label}"
          activation = generate_activation_fixture(
              output,
              response,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              execution_stage="application-container",
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/provider-state-test/host-{label}.nix"
          write_activation_host(host, activation)
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_foreground(host, label):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-state-settle-{shlex.quote(label)}",
              timeout=1200,
          )
          return EFFECT_FLIGHT.current_generation()


      def replace_foreground_identity(value):
          if isinstance(value, str):
              return (
                  value.replace("nginx-main", "nginx-secondary")
                  .replace("18081", "18082")
                  .replace("18443", "18444")
              )
          if isinstance(value, list):
              return [replace_foreground_identity(child) for child in value]
          if isinstance(value, dict):
              return {
                  key: replace_foreground_identity(child)
                  for key, child in value.items()
              }
          return value


      def foreground_pair(label, method):
          if method == "start":
              return (
                  foreground_activation(label + "-retained", "full", "retained"),
                  foreground_activation(
                      label + "-predecessor", "disable-main", "predecessor"
                  ),
              )
          if method == "stop":
              return (
                  foreground_activation(
                      label + "-retained", "disable-main", "retained"
                  ),
                  foreground_activation(label + "-predecessor", "full", "predecessor"),
              )
          if method != "observe":
              raise RuntimeError(f"unknown foreground method {method!r}")
          return (
              foreground_activation(label + "-retained", "full", "retained"),
              foreground_activation(label + "-predecessor", "full", "predecessor"),
          )


      for index, state_cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, scenario = state_cell_id.split("/")
          assert adapter == "foreground-process", state_cell_id
          label = f"provider-state-foreground-{index:03d}"
          retained_host, predecessor_host = foreground_pair(label, method)
          retained_generation = settle_foreground(
              retained_host, label + "-retained"
          )
          predecessor_generation = settle_foreground(
              predecessor_host, label + "-predecessor"
          )
          flight_cell_id = "/".join(
              state_cell_id.split("/")[:-1]
              + ["interrupt-after-acquisition"]
          )
          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=flight_cell_id,
              interface=interface,
              method=method,
              provider_key="shared-service",
              resource_key="nginx-main-service",
              label=label,
          )

          def observe_foreground(operation, cell_id=flight_cell_id):
              foreign = {
                  "adapter": "foreground-process",
                  "operation": replace_foreground_identity(operation),
              }
              return EFFECT_ORACLES.observe_resource(
                  cell_id, operation, foreign
              )

          if scenario == "activate-retained-target":
              bridge = PROVIDER_STATE_FLIGHT.RetainedTargetBridge(
                  state_builder=STATE_BUILDER,
                  state_cell_id=state_cell_id,
                  flight_cell_id=flight_cell_id,
                  retained_generation=retained_generation,
                  predecessor_generation=predecessor_generation,
                  observe=observe_foreground,
              )
              EFFECT_FLIGHT.run_effect_flight(
                  flight,
                  retained_host,
                  bridge,
                  observe_foreground,
                  on_acquisition=bridge.on_acquisition,
                  launch=PROVIDER_STATE_FLIGHT.retained_rollback_launcher(
                      retained_generation
                  ),
              )
          else:
              PROVIDER_STATE_FLIGHT.run_unsupported_transfer_flight(
                  flight,
                  state_cell_id,
                  retained_host,
                  STATE_BUILDER,
                  observe_foreground,
                  FIXTURE,
              )
    '';
  }
