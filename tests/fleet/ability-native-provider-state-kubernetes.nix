##! Production provider-state flights for Kubernetes objects and K3s bootstrap.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    providerStateQualification = true;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-state-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-provider-state-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-state-kubernetes";
    qualifiedCells = cells.groups.kubernetes;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_kubernetes_packages()


      def kubernetes_activation(label, replicas, include_longhorn, lifecycle="full"):
          output = f"/var/lib/aos/provider-state-test/activation-{label}"
          authority = f"/var/lib/aos/provider-state-test/authority-{label}"
          activation = generate_kubernetes_activation(
              output,
              replicas,
              include_longhorn,
              authority,
              lifecycle=lifecycle,
              provider_incarnation_revision=label,
          )
          provision_kubernetes_authority(activation, authority)
          host = f"/var/lib/aos/provider-state-test/host-{label}.nix"
          write_kubernetes_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_kubernetes(host, label):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-state-kubernetes-{shlex.quote(label)}",
              timeout=1800,
          )
          return EFFECT_FLIGHT.current_generation()


      def replace_kubernetes_object(value, source, destination):
          if isinstance(value, str):
              return value.replace(source, destination)
          if isinstance(value, list):
              return [
                  replace_kubernetes_object(child, source, destination)
                  for child in value
              ]
          if isinstance(value, dict):
              return {
                  key: replace_kubernetes_object(child, source, destination)
                  for key, child in value.items()
              }
          return value


      def replace_bootstrap_foreign(value):
          if isinstance(value, str):
              return (
                  value.replace("server-service", "matrix-foreign-service")
                  .replace("k3s.service", "aos-kubernetes-matrix-foreign.service")
              )
          if isinstance(value, list):
              return [replace_bootstrap_foreign(child) for child in value]
          if isinstance(value, dict):
              return {
                  key: replace_bootstrap_foreign(child)
                  for key, child in value.items()
              }
          return value


      def kubernetes_pair(label, adapter, method, scenario):
          if adapter == "kubernetes-object" and method in {"apply", "observe"}:
              return (
                  kubernetes_activation(f"{label}-retained", 2, True),
                  kubernetes_activation(f"{label}-predecessor", 1, True),
                  "k3s",
                  "cilium-helmchart",
              )
          if adapter == "kubernetes-object" and method == "delete":
              return (
                  kubernetes_activation(f"{label}-retained", 1, False),
                  kubernetes_activation(f"{label}-predecessor", 1, True),
                  "k3s",
                  "longhorn-helmchart",
              )
          if adapter == "systemd-bootstrap" and method == "start":
              return (
                  kubernetes_activation(f"{label}-retained", 1, True),
                  kubernetes_activation(
                      f"{label}-predecessor",
                      2,
                      True,
                      lifecycle="full",
                  ),
                  "k3s",
                  "server-service",
              )
          if adapter == "systemd-bootstrap" and method == "stop":
              return (
                  kubernetes_activation(
                      f"{label}-retained", 1, True, lifecycle="remove"
                  ),
                  kubernetes_activation(f"{label}-predecessor", 1, True),
                  "k3s",
                  "server-service",
              )
          assert adapter == "systemd-bootstrap" and method == "observe-manager"
          return (
              kubernetes_activation(f"{label}-retained", 2, True),
              kubernetes_activation(f"{label}-predecessor", 1, True),
              "k3s",
              "server-service",
          )


      for index, state_cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, scenario = state_cell_id.split("/")
          label = f"provider-state-kubernetes-{index:03d}"
          (
              retained_host,
              predecessor_host,
              target_provider,
              target_resource,
          ) = kubernetes_pair(label, adapter, method, scenario)
          retained_generation = settle_kubernetes(
              retained_host, label + "-retained"
          )
          predecessor_generation = settle_kubernetes(
              predecessor_host, label + "-predecessor"
          )
          flight_cell_id = "/".join(
              state_cell_id.split("/")[:-1] + ["interrupt-after-acquisition"]
          )
          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=flight_cell_id,
              interface=interface,
              method=method,
              provider_key=target_provider,
              resource_key=target_resource,
              label=label,
          )

          def observe_kubernetes(operation, adapter=adapter, method=method):
              if adapter == "kubernetes-object":
                  source = "longhorn" if method == "delete" else "cilium"
                  destination = "cilium" if method == "delete" else "longhorn"
                  foreign_operation = replace_kubernetes_object(
                      operation, source, destination
                  )
                  foreign_adapter = adapter
              else:
                  foreign_operation = replace_bootstrap_foreign(operation)
                  foreign_adapter = "systemd-bootstrap"
              return EFFECT_ORACLES.observe_resource(
                  flight_cell_id,
                  operation,
                  {"adapter": foreign_adapter, "operation": foreign_operation},
              )

          if scenario == "activate-retained-target":
              bridge = PROVIDER_STATE_FLIGHT.RetainedTargetBridge(
                  state_builder=STATE_BUILDER,
                  state_cell_id=state_cell_id,
                  flight_cell_id=flight_cell_id,
                  retained_generation=retained_generation,
                  predecessor_generation=predecessor_generation,
                  source_authority=PROVIDER_STATE_FLIGHT.generation_runtime_authority(
                      predecessor_generation
                  ),
                  observe=observe_kubernetes,
              )
              EFFECT_FLIGHT.run_effect_flight(
                  flight,
                  retained_host,
                  bridge,
                  observe_kubernetes,
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
                  observe_kubernetes,
                  FIXTURE,
              )
    '';
  }
