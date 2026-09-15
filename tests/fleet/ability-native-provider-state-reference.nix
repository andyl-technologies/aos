##! Production provider-state flights for the reference nginx provider stack.
{
  lib,
  mkSystem,
  pkgs,
  nativeAdapterMatrix,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    providerStateQualification = true;
  };
  matrix = nativeAdapterMatrix;
  cells = import ./_ability-provider-state-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-provider-state-cohort.nix {
    inherit lib mkSystem pkgs fixture nativeAdapterMatrix;
    name = "ability-native-provider-state-reference";
    qualifiedCells = cells.groups.reference;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()
      def reference_activation(
          label,
          lifecycle,
          response,
          tls,
          systemd_manager_method=None,
      ):
          output = f"/var/lib/aos/provider-state-test/activation-{label}"
          authority = f"/var/lib/aos/provider-state-test/authority-{label}"
          arguments = {}
          if tls:
              tls_bundle, _, _ = create_tls_bundle(
                  f"/var/lib/aos/provider-state-test/tls-{label}",
                  "matrix.example",
                  4501,
              )
              tls_version = "sha256:" + runtime.succeed(
                  f"{COREUTILS}/sha256sum {shlex.quote(tls_bundle)}"
              ).split()[0]
              arguments = {"tls_version": tls_version, "tls_bundle": tls_bundle}
          activation = generate_activation_fixture(
              output,
              response,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              systemd_manager_method=systemd_manager_method,
              systemd_manager_revision=(
                  f"matrix-{label}"
                  if systemd_manager_method is not None
                  else None
              ),
              provider_incarnation_revision=label,
              **arguments,
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/provider-state-test/host-{label}.nix"
          write_activation_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_reference(host, label):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-state-settle-{shlex.quote(label)}",
              timeout=1200,
          )
          return EFFECT_FLIGHT.current_generation()


      def reference_target(adapter):
          if adapter == "systemd-manager":
              return "matrix-systemd", "aos-matrix-primary-service"
          if adapter == "credential-delivery":
              return "shared-credential", "nginx-main-credential-view"
          if adapter == "managed-configuration":
              return "shared-configuration", "nginx-main-configuration"
          if adapter == "service-management":
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


      def replace_reference_identity(value):
          if isinstance(value, str):
              return (
                  value.replace("nginx-main", "nginx-secondary")
                  .replace("18081", "18082")
                  .replace("18443", "18444")
              )
          if isinstance(value, list):
              return [replace_reference_identity(child) for child in value]
          if isinstance(value, dict):
              return {
                  key: replace_reference_identity(child)
                  for key, child in value.items()
              }
          return value


      def replace_systemd_foreign(value):
          if isinstance(value, str):
              return value.replace("aos-matrix-primary", "aos-matrix-foreign")
          if isinstance(value, list):
              return [replace_systemd_foreign(child) for child in value]
          if isinstance(value, dict):
              return {
                  key: replace_systemd_foreign(child)
                  for key, child in value.items()
              }
          return value


      def reference_pair(label, adapter, method, scenario):
          if adapter == "systemd-manager":
              retained = reference_activation(
                  f"{label}-retained", "full", "retained", True, method
              )
              predecessor = reference_activation(
                  f"{label}-predecessor",
                  "full",
                  "predecessor",
                  True,
                  method,
              )
              return retained, predecessor
          if adapter == "credential-delivery" and method == "deliver":
              return (
                  reference_activation(f"{label}-retained", "full", "retained", True),
                  reference_activation(
                      f"{label}-predecessor",
                      "full",
                      "predecessor",
                      True,
                  ),
              )
          if adapter == "credential-delivery" and method == "release":
              return (
                  reference_activation(f"{label}-retained", "full", "retained", False),
                  reference_activation(
                      f"{label}-predecessor", "full", "predecessor", True
                  ),
              )
          if method in {"deliver", "materialize", "apply", "ensure", "start"}:
              return (
                  reference_activation(f"{label}-retained", "full", "retained", True),
                  reference_activation(
                      f"{label}-predecessor",
                      "full",
                      "predecessor",
                      True,
                  ),
              )
          if method in {"release", "remove", "stop"}:
              return (
                  reference_activation(
                      f"{label}-retained", "disable-main", "retained", True
                  ),
                  reference_activation(
                      f"{label}-predecessor", "full", "predecessor", True
                  ),
              )
          return (
              reference_activation(f"{label}-retained", "full", "retained", True),
              reference_activation(
                  f"{label}-predecessor", "full", "predecessor", True
              ),
          )


      for index, state_cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, scenario = state_cell_id.split("/")
          label = f"provider-state-reference-{index:03d}"
          retained_host, predecessor_host = reference_pair(
              label, adapter, method, scenario
          )
          retained_generation = settle_reference(retained_host, label + "-retained")
          predecessor_generation = settle_reference(
              predecessor_host, label + "-predecessor"
          )
          target_provider, target_resource = reference_target(adapter)
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

          def observe_reference(operation, cell_id=flight_cell_id, adapter=adapter):
              foreign = {
                  "adapter": adapter,
                  "operation": (
                      replace_systemd_foreign(operation)
                      if adapter == "systemd-manager"
                      else replace_reference_identity(operation)
                  ),
              }
              return EFFECT_ORACLES.observe_resource(cell_id, operation, foreign)

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
                  observe=observe_reference,
              )
              EFFECT_FLIGHT.run_effect_flight(
                  flight,
                  retained_host,
                  bridge,
                  observe_reference,
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
                  observe_reference,
                  FIXTURE,
              )
    '';
  }
