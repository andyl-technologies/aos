##! Production cancellation flights for Kubernetes objects and K3s bootstrap.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    effectQualification = true;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-cancellation-cells.nix {
    inherit lib matrix;
  };
  bootstrapCells =
    builtins.filter (
      cellId: builtins.head (lib.splitString "/" cellId) == "systemd-bootstrap"
    )
    cells.groups.systemd;
in
  import ./_ability-cancellation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-cancellation-kubernetes";
    qualifiedCells = cells.groups.kubernetes ++ bootstrapCells;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_kubernetes_packages()


      def kubernetes_activation(label, replicas, include_longhorn, lifecycle="full"):
          output = f"/var/lib/aos/ability-boundary-test/activation-{label}"
          authority = f"/var/lib/aos/ability-boundary-test/authority-{label}"
          activation = generate_kubernetes_activation(
              output,
              replicas,
              include_longhorn,
              authority,
              lifecycle=lifecycle,
          )
          provision_kubernetes_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/host-{label}.nix"
          write_kubernetes_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}")
          return host


      def settle_kubernetes(label, replicas, include_longhorn, lifecycle="full"):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          host = kubernetes_activation(
              label, replicas, include_longhorn, lifecycle
          )
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/kubernetes-cancel-baseline-{shlex.quote(label)}",
              timeout=1800,
          )


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


      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          label = f"kubernetes-cancel-{index:03d}"
          baseline_label = f"{label}-baseline"

          if adapter == "kubernetes-object" and method in {"apply", "observe"}:
              settle_kubernetes(baseline_label, 1, True)
              candidate = kubernetes_activation(label, 2, True)
              target_provider = "k3s"
              target_resource = "cilium-helmchart"
          elif adapter == "kubernetes-object" and method == "delete":
              settle_kubernetes(baseline_label, 1, True)
              candidate = kubernetes_activation(label, 1, False)
              target_provider = "k3s"
              target_resource = "longhorn-helmchart"
          elif adapter == "systemd-bootstrap" and method == "stop":
              settle_kubernetes(baseline_label, 1, True)
              candidate = kubernetes_activation(label, 1, True, lifecycle="remove")
              target_provider = "k3s"
              target_resource = "server-service"
          else:
              assert adapter == "systemd-bootstrap" and method == "observe-manager"
              settle_kubernetes(baseline_label, 1, True)
              candidate = kubernetes_activation(label, 2, True)
              target_provider = "k3s"
              target_resource = "server-service"

          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=cell_id,
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
                  cell_id,
                  operation,
                  {"adapter": foreign_adapter, "operation": foreign_operation},
              )

          EFFECT_FLIGHT.run_cancellation_flight(
              flight, candidate, CANCELLATION_BUILDER, observe_kubernetes
          )
    '';
  }
