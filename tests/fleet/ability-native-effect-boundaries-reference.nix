##! Production interruption flights for the reference nginx provider stack.
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
  cells = import ./_ability-effect-boundary-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-effect-boundary-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-effect-boundaries-reference";
    qualifiedCells = cells.groups.reference ++ cells.groups.systemdManager;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()
      tls_bundle, _, _ = create_tls_bundle(
          "/var/lib/aos/ability-boundary-test/tls", "matrix.example", 4401
      )
      tls_version = "sha256:" + runtime.succeed(
          f"{COREUTILS}/sha256sum {shlex.quote(tls_bundle)}"
      ).split()[0]


      def reference_activation(
          label,
          lifecycle,
          response,
          tls,
          systemd_manager_method=None,
      ):
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
              systemd_manager_method=systemd_manager_method,
              systemd_manager_revision=(
                  f"matrix-{label}"
                  if systemd_manager_method is not None
                  else None
              ),
              **arguments,
          )
          provision_operator_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/host-{label}.nix"
          write_activation_host(host, activation, OBSERVER_HOST_MODULE)
          runtime.succeed(f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}")
          return host


      def settle_reference(label, lifecycle, response, tls):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          host = reference_activation(label, lifecycle, response, tls)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/reference-baseline-{shlex.quote(label)}",
              timeout=1200,
          )


      def reference_target(adapter, method):
          if adapter == "systemd-manager":
              return "matrix-systemd", "aos-matrix-primary-service"
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


      mutation_methods = {
          "prepare", "publish", "record", "validate", "reload"
      }
      creation_methods = {"deliver", "materialize", "apply", "ensure", "start"}
      teardown_methods = {"release", "remove", "stop"}
      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          label = f"reference-{index:03d}"
          baseline_label = f"{label}-baseline"
          target_provider, target_resource = reference_target(adapter, method)

          if adapter == "systemd-manager":
              baseline_method = "stop" if method == "start" else "start"
              settle_reference(
                  baseline_label, "full", "baseline", True,
              )
              baseline_host = reference_activation(
                  f"{baseline_label}-systemd",
                  "full",
                  "baseline",
                  True,
                  baseline_method,
              )
              runtime.succeed(
                  f"{APM} switch --from {shlex.quote(baseline_host)} "
                  f"--eval-root /run/reference-systemd-baseline-{index:03d}",
                  timeout=1200,
              )
              candidate = reference_activation(
                  label, "full", label, True, method
              )
          elif adapter == "credential-delivery" and method == "deliver":
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
              assert method in mutation_methods or method in {
                  "acquire", "observe"
              }, (adapter, method)
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
                  "operation": (
                      replace_systemd_foreign(operation)
                      if adapter == "systemd-manager"
                      else replace_reference_identity(operation)
                  ),
              }
              return EFFECT_ORACLES.observe_resource(
                  cell_id, operation, foreign
              )

          EFFECT_FLIGHT.run_effect_flight(
              flight, candidate, EFFECT_BUILDER, observe_reference
          )
    '';
  }
