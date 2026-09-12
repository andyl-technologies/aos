##! Production cancellation flights for host systemd manager adapters.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    effectQualification = true;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-cancellation-cells.nix {
    inherit lib matrix;
  };
  qualifiedCells =
    builtins.filter (
      cellId: builtins.head (lib.splitString "/" cellId) != "systemd-bootstrap"
    )
    cells.groups.systemd;
in
  import ./_ability-cancellation-cohort.nix {
    inherit lib mkSystem pkgs fixture qualifiedCells;
    name = "ability-native-cancellation-systemd";
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()


      def reference_activation(label, lifecycle, systemd_manager_method=None):
          output = f"/var/lib/aos/ability-boundary-test/activation-{label}"
          authority = f"/var/lib/aos/ability-boundary-test/authority-{label}"
          activation = generate_activation_fixture(
              output,
              label,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              systemd_manager_method=systemd_manager_method,
              systemd_manager_revision=(
                  f"matrix-{label}"
                  if systemd_manager_method is not None
                  else None
              ),
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/host-{label}.nix"
          write_activation_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}")
          return host


      def settle_reference(label, lifecycle, systemd_manager_method=None):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          host = reference_activation(label, lifecycle, systemd_manager_method)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/systemd-cancel-baseline-{shlex.quote(label)}",
              timeout=1200,
          )


      def replace_reference_identity(value):
          if isinstance(value, str):
              return value.replace("nginx-main", "nginx-secondary")
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


      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          label = f"systemd-cancel-{index:03d}"
          baseline_label = f"{label}-baseline"

          if adapter == "systemd-manager":
              settle_reference(baseline_label, "full", "start")
              candidate = reference_activation(label, "full", method)
              target_provider = "matrix-systemd"
              target_resource = "aos-matrix-primary-service"
          else:
              assert adapter == "systemd-service-legacy", adapter
              if method == "stop":
                  settle_reference(baseline_label, "full")
                  candidate = reference_activation(label, "disable-main")
              else:
                  assert method == "observe", method
                  settle_reference(baseline_label, "full")
                  candidate = reference_activation(label, "full")
              target_provider = "shared-service"
              target_resource = "nginx-main-service"

          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=cell_id,
              interface=interface,
              method=method,
              provider_key=target_provider,
              resource_key=target_resource,
              label=label,
          )

          def observe_systemd(operation, cell_id=cell_id, adapter=adapter):
              foreign_operation = (
                  replace_systemd_foreign(operation)
                  if adapter == "systemd-manager"
                  else replace_reference_identity(operation)
              )
              return EFFECT_ORACLES.observe_resource(
                  cell_id,
                  operation,
                  {"adapter": adapter, "operation": foreign_operation},
              )

          EFFECT_FLIGHT.run_cancellation_flight(
              flight, candidate, CANCELLATION_BUILDER, observe_systemd
          )
    '';
  }
