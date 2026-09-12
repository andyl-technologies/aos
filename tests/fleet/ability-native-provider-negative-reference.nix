##! Provider-negative qualification flights for the production nginx stack.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    transitionTransform = import ../abilities/provider-negative-transition.nix {inherit lib;};
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-negative-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-provider-negative-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-negative-reference";
    qualifiedCells = cells.groups.reference;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()
      tls_bundle, _, _ = create_tls_bundle(
          "/var/lib/aos/ability-provider-negative/tls", "matrix.example", 5501
      )
      tls_version = "sha256:" + runtime.succeed(
          f"{COREUTILS}/sha256sum {shlex.quote(tls_bundle)}"
      ).split()[0]


      def activation(label, lifecycle, response, tls):
          output = f"/var/lib/aos/ability-provider-negative/activation-{label}"
          authority = f"/var/lib/aos/ability-provider-negative/authority-{label}"
          arguments = {}
          if tls:
              arguments = {"tls_version": tls_version, "tls_bundle": tls_bundle}
          selected = generate_activation_fixture(
              output,
              response,
              response,
              authority,
              lifecycle=lifecycle,
              **arguments,
          )
          provision_operator_authority(selected, authority)
          host = f"/var/lib/aos/ability-provider-negative/host-{label}.nix"
          write_activation_host(host, selected, OBSERVER_HOST_MODULE)
          return host, selected


      def settle(label, lifecycle, response, tls):
          host, selected = activation(label, lifecycle, response, tls)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-negative-baseline-{shlex.quote(label)}",
              timeout=1200,
          )
          return selected


      def resource_map(*activations):
          entries = {}
          for activation_document in activations:
              for mapping in activation_document["native_resource_map"]["entries"]:
                  entries[json.dumps(mapping["resource"], sort_keys=True)] = mapping
          return {"entries": list(entries.values())}


      def target(adapter):
          if adapter == "credential-delivery":
              return "shared-credential", "nginx-main-credential-view"
          if adapter == "managed-configuration":
              return "shared-configuration", "nginx-main-configuration"
          if adapter == "systemd-service-legacy":
              return "shared-service", "nginx-main-service"
          if adapter == "nginx-validation":
              return "nginx-main", "virtual-hosts"
          if adapter == "host-storage":
              return "nginx-main", "logs-storage"
          if adapter == "network-endpoint":
              return "nginx-main", "http-endpoint-18081"
          if adapter == "host-network-policy":
              return "nginx-main", "http-network-policy-18081"
          raise RuntimeError(f"unknown reference adapter {adapter!r}")


      matrix_cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      methods = sorted({
          tuple(cell_id.split("/")[:4])
          for cell_id in COHORT_CELLS
      })
      creation_methods = {"apply", "ensure", "materialize"}
      teardown_methods = {"release", "remove", "stop"}
      for index, (adapter, interface, _, method) in enumerate(methods):
          label = f"reference-{index:03d}"
          if adapter == "credential-delivery" and method == "deliver":
              baseline = settle(f"{label}-baseline", "full", "baseline", False)
              candidate, selected = activation(label, "full", label, True)
          elif adapter == "credential-delivery" and method == "release":
              baseline = settle(f"{label}-baseline", "full", "baseline", True)
              candidate, selected = activation(label, "full", label, False)
          elif method in creation_methods:
              baseline = settle(f"{label}-baseline", "remove-all", "baseline", True)
              candidate, selected = activation(label, "full", label, True)
          elif method in teardown_methods:
              baseline = settle(f"{label}-baseline", "full", "baseline", True)
              candidate, selected = activation(label, "remove-all", label, True)
          elif method == "start":
              baseline = settle(f"{label}-baseline", "disable-all", "baseline", True)
              candidate, selected = activation(label, "full", label, True)
          else:
              baseline = settle(f"{label}-baseline", "full", "baseline", True)
              candidate, selected = activation(label, "full", label, True)

          provider_key, resource_key = target(adapter)
          mappings = resource_map(baseline, selected)
          foreign_cell = (
              f"{adapter}/{interface}/abi-1/{method}/"
              "reject-foreign-resource-mutation"
          )
          PROVIDER_FLIGHT.run_provider_flight(
              PROVIDER_FLIGHT.ProviderFlight(
                  adapter=adapter,
                  interface=interface,
                  method=method,
                  provider_key=provider_key,
                  resource_key=resource_key,
                  label=label,
                  observation=matrix_cells[foreign_cell]["effect_class"]
                  == "observation",
                  mapping=mappings,
              ),
              candidate,
              PROVIDER_BUILDER,
          )
    '';
  }
