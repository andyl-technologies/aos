##! Supported-cancellation flights for the reference nginx provider stack.
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
    name = "ability-native-cancellation-reference";
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
          "/var/lib/aos/ability-boundary-test/tls", "cancel.example", 4701
      )
      tls_version = "sha256:" + runtime.succeed(
          f"{COREUTILS}/sha256sum {shlex.quote(tls_bundle)}"
      ).split()[0]
      def reference_activation(label, lifecycle, response, tls):
          output = f"/var/lib/aos/ability-boundary-test/activation-{label}"
          authority = f"/var/lib/aos/ability-boundary-test/authority-{label}"
          arguments = {}
          if tls:
              arguments = {"tls_version": tls_version, "tls_bundle": tls_bundle}
          activation = generate_activation_fixture(
              output,
              response,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              **arguments,
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/host-{label}.nix"
          write_activation_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_reference(label, lifecycle, response, tls):
          runtime.succeed(
              f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET} "
              f"{EFFECT_FLIGHT.CONTINUE}"
          )
          host = reference_activation(label, lifecycle, response, tls)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/reference-cancel-baseline-{shlex.quote(label)}",
              timeout=1200,
          )


      def settle_cancelled_flight():
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          runtime.succeed(f"{SYSTEMCTL} restart aos-activate.service")
          runtime.wait_until_succeeds(
              f"{SYSTEMCTL} is-active --quiet aos-activate.service",
              timeout=900,
          )


      def reference_target(adapter):
          if adapter == "credential-delivery":
              return "shared-credential", "nginx-main-credential-view"
          if adapter == "managed-configuration":
              return "shared-configuration", "nginx-main-configuration"
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


      creation_methods = {"deliver", "materialize", "apply", "ensure"}
      teardown_methods = {"release", "remove"}
      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          label = f"reference-cancel-{index:02d}"
          baseline_label = f"{label}-baseline"
          target_provider, target_resource = reference_target(adapter)

          if adapter == "credential-delivery" and method == "deliver":
              settle_reference(baseline_label, "full", "baseline", False)
              candidate = reference_activation(label, "full", label, True)
          elif adapter == "credential-delivery" and method == "release":
              settle_reference(baseline_label, "full", "baseline", True)
              candidate = reference_activation(label, "full", label, False)
          elif method in creation_methods:
              settle_reference(baseline_label, "disable-main", "baseline", True)
              candidate = reference_activation(label, "full", label, True)
          elif method in teardown_methods:
              settle_reference(baseline_label, "full", "baseline", True)
              candidate = reference_activation(label, "disable-main", label, True)
          else:
              settle_reference(baseline_label, "full", "baseline", True)
              candidate = reference_activation(label, "full", label, True)

          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=cell_id,
              interface=interface,
              method=method,
              provider_key=target_provider,
              resource_key=target_resource,
              label=label,
          )

          def observe_reference(operation, cell_id=cell_id, adapter=adapter):
              foreign = {
                  "adapter": adapter,
                  "operation": replace_reference_identity(operation),
              }
              return EFFECT_ORACLES.observe_resource(
                  cell_id, operation, foreign
              )

          EFFECT_FLIGHT.run_cancellation_flight(
              flight, candidate, CANCELLATION_BUILDER, observe_reference
          )
          settle_cancelled_flight()

    '';
  }
