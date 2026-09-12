##! Production interruption flights for Kubernetes objects and K3s bootstrap.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  effectBoundary = import ../abilities/effect-boundary-transition.nix {inherit lib;};
  kubernetesEffect = import ../abilities/kubernetes-effect-boundary-transition.nix {inherit lib;};
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    transitionTransform = transition: effectBoundary (kubernetesEffect transition);
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-effect-boundary-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-effect-boundary-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-effect-boundaries-kubernetes";
    qualifiedCells = cells.groups.kubernetes;
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
              f"--eval-root /run/kubernetes-baseline-{shlex.quote(label)}",
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
          label = f"kubernetes-{index:03d}"
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
          elif adapter == "systemd-bootstrap" and method == "start":
              settle_kubernetes(baseline_label, 1, True, lifecycle="remove")
              candidate = kubernetes_activation(label, 1, True)
              target_provider = "k3s"
              target_resource = "server-service"
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

          EFFECT_FLIGHT.run_effect_flight(
              flight, candidate, EFFECT_BUILDER, observe_kubernetes
          )
    '';
  }
