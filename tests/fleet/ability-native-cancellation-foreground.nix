##! Supported-cancellation flights for reference foreground nginx processes.
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
in
  import ./_ability-cancellation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-cancellation-foreground";
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
          output = f"/var/lib/aos/ability-boundary-test/activation-{label}"
          authority = f"/var/lib/aos/ability-boundary-test/authority-{label}"
          activation = generate_activation_fixture(
              output,
              response,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              execution_stage="application-container",
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/host-{label}.nix"
          write_activation_host(
              host,
              activation,
              OBSERVER_HOST_MODULE,
              include_nginx_units=False,
          )
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_foreground(label, lifecycle, response):
          runtime.succeed(
              f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET} "
              f"{EFFECT_FLIGHT.CONTINUE}"
          )
          host = foreground_activation(label, lifecycle, response)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/foreground-cancel-baseline-{shlex.quote(label)}",
              timeout=1200,
          )


      def settle_cancelled_flight():
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          runtime.succeed(f"{SYSTEMCTL} restart aos-activate.service")
          runtime.wait_until_succeeds(
              f"{SYSTEMCTL} is-active --quiet aos-activate.service",
              timeout=900,
          )


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


      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          label = f"foreground-cancel-{index:02d}"
          baseline_label = f"{label}-baseline"

          if method == "start":
              settle_foreground(baseline_label, "disable-main", "baseline")
              candidate = foreground_activation(label, "full", label)
          elif method == "stop":
              settle_foreground(baseline_label, "full", "baseline")
              candidate = foreground_activation(label, "disable-main", label)
          else:
              settle_foreground(baseline_label, "full", "baseline")
              candidate = foreground_activation(label, "full", label)

          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=cell_id,
              interface=interface,
              method=method,
              provider_key="shared-service",
              resource_key="nginx-main-service",
              label=label,
          )

          def observe_foreground(
              operation, cell_id=cell_id, adapter=adapter
          ):
              foreign = {
                  "adapter": adapter,
                  "operation": replace_foreground_identity(operation),
              }
              return EFFECT_ORACLES.observe_resource(
                  cell_id, operation, foreign
              )

          EFFECT_FLIGHT.run_cancellation_flight(
              flight, candidate, CANCELLATION_BUILDER, observe_foreground
          )
          settle_cancelled_flight()

    '';
  }
