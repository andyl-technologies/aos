##! Provider-negative qualification flights for K3s bootstrap and Kubernetes objects.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  providerNegative = import ../abilities/provider-negative-transition.nix {inherit lib;};
  kubernetesEffect = import ../abilities/kubernetes-effect-boundary-transition.nix {inherit lib;};
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    bootstrapMatrix = true;
    transitionTransform = transition: providerNegative (kubernetesEffect transition);
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-negative-cells.nix {inherit lib matrix;};
in
  import ./_ability-provider-negative-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-negative-kubernetes";
    qualifiedCells = cells.groups.kubernetes;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_kubernetes_packages()


      def activation(
          label,
          replicas,
          include_longhorn,
          lifecycle="full",
      ):
          output = f"/var/lib/aos/ability-provider-negative/kubernetes-{label}"
          authority = f"/var/lib/aos/ability-provider-negative/kubernetes-authority-{label}"
          selected = generate_kubernetes_activation(
              output,
              replicas,
              include_longhorn,
              authority,
              lifecycle=lifecycle,
          )
          provision_kubernetes_authority(selected, authority)
          host = f"/var/lib/aos/ability-provider-negative/kubernetes-host-{label}.nix"
          write_kubernetes_host(host, selected, OBSERVER_HOST_MODULE)
          return host, selected


      def settle(label, replicas, include_longhorn, lifecycle="full"):
          host, selected = activation(
              label, replicas, include_longhorn, lifecycle
          )
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-negative-kubernetes-{shlex.quote(label)}",
              timeout=1200,
          )
          return selected


      def resource_map(*activations):
          entries = {}
          for activation_document in activations:
              for mapping in activation_document["native_resource_map"]["entries"]:
                  entries[json.dumps(mapping["resource"], sort_keys=True)] = mapping
          return {"entries": list(entries.values())}


      matrix_cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      methods = sorted({
          (cell_id.split("/")[0], cell_id.split("/")[3])
          for cell_id in COHORT_CELLS
      })
      for index, (adapter, method) in enumerate(methods):
          label = f"kubernetes-{index:03d}"
          if adapter == "kubernetes-object" and method in {"apply", "observe"}:
              baseline = settle(
                  f"{label}-baseline", 1, False
              )
              runtime.wait_until_succeeds(
                  f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
                  "get helmchart cilium -n kube-system -o name",
                  timeout=600,
              )
              candidate, selected = activation(label, 2, True)
              provider_key = "k3s"
              resource_key = "cilium-helmchart"
          elif adapter == "kubernetes-object" and method == "delete":
              baseline = settle(
                  f"{label}-baseline", 1, True
              )
              runtime.wait_until_succeeds(
                  f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
                  "get helmchart cilium -n kube-system -o name",
                  timeout=600,
              )
              candidate, selected = activation(label, 1, True, "remove")
              provider_key = "k3s"
              resource_key = "cilium-helmchart"
          elif adapter == "systemd-bootstrap" and method == "stop":
              baseline = settle(
                  f"{label}-baseline", 1, False
              )
              candidate, selected = activation(label, 1, False, "remove")
              provider_key = "k3s"
              resource_key = "matrix-secondary-service"
          elif adapter == "systemd-bootstrap" and method == "start":
              baseline = settle(
                  f"{label}-baseline", 1, False, "remove"
              )
              candidate, selected = activation(label, 1, False)
              provider_key = "k3s"
              resource_key = "matrix-secondary-service"
          else:
              assert adapter == "systemd-bootstrap" and method == "observe-manager", (
                  adapter,
                  method,
              )
              baseline = settle(
                  f"{label}-baseline", 1, False
              )
              candidate, selected = activation(label, 1, False)
              provider_key = "k3s"
              resource_key = "matrix-secondary-service"

          foreign_cell = (
              f"{adapter}/"
              + (
                  "aos.kubernetes-object-effects"
                  if adapter == "kubernetes-object"
                  else "aos.systemd-provider-bootstrap"
              )
              + f"/abi-1/{method}/reject-foreign-resource-mutation"
          )
          PROVIDER_FLIGHT.run_provider_flight(
              PROVIDER_FLIGHT.ProviderFlight(
                  adapter=adapter,
                  interface=foreign_cell.split("/")[1],
                  method=method,
                  provider_key=provider_key,
                  resource_key=resource_key,
                  label=label,
                  observation=matrix_cells[foreign_cell]["effect_class"]
                  == "observation",
                  mapping=resource_map(baseline, selected),
              ),
              candidate,
              PROVIDER_BUILDER,
          )
    '';
  }
