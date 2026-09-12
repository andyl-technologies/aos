##! Real OCI foreground-process dependency and foreign-authority flights.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-foreground-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    effectQualification = true;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-negative-cells.nix {inherit lib matrix;};
in
  import ./_ability-provider-negative-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-negative-foreground";
    qualifiedCells = cells.groups.foreground-process;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()


      def foreground_activation(label, lifecycle, response):
          output = f"/var/lib/aos/ability-provider-negative/activation-{label}"
          authority = f"/var/lib/aos/ability-provider-negative/authority-{label}"
          selected = generate_activation_fixture(
              output,
              response,
              "foreign-stable",
              authority,
              lifecycle=lifecycle,
              execution_stage="application-container",
          )
          provision_operator_authority(selected, authority)
          host = f"/var/lib/aos/ability-provider-negative/host-{label}.nix"
          write_activation_host(host, selected)
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host, selected


      def settle_foreground(label, lifecycle, response):
          runtime.succeed(f"{COREUTILS}/rm -f {PROVIDER_FLIGHT.TARGET}")
          host, selected = foreground_activation(label, lifecycle, response)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/foreground-baseline-{shlex.quote(label)}",
              timeout=1200,
          )
          return selected


      def resource_map(*activations):
          entries = {}
          for activation_document in activations:
              for mapping in activation_document["native_resource_map"]["entries"]:
                  entries[json.dumps(mapping["resource"], sort_keys=True)] = mapping
          return {"entries": list(entries.values())}


      def observe_secondary_foreground(state, mappings):
          secondary = [
              mapping
              for mapping in mappings["entries"]
              if mapping["resource"]["provider"]["key"] == "shared-service"
              and mapping["resource"]["key"] == "nginx-secondary-service"
          ]
          assert len(secondary) == 1, secondary
          operation = dict(state["foreign"])
          operation["resource"] = secondary[0]["resource"]
          operation["target"] = dict(operation["target"])
          operation["target"]["resource"] = secondary[0]["resource"]
          return PROVIDER_ORACLES.observe_canonical_foreground(
              operation, mappings
          )


      matrix_cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      methods = sorted({cell_id.split("/")[3] for cell_id in COHORT_CELLS})
      for index, method in enumerate(methods):
          label = f"foreground-{index:03d}"
          baseline_label = f"{label}-baseline"
          if method == "start":
              baseline = settle_foreground(
                  baseline_label, "disable-main", "baseline"
              )
              candidate, selected = foreground_activation(label, "full", label)
          elif method == "stop":
              baseline = settle_foreground(baseline_label, "full", "baseline")
              candidate, selected = foreground_activation(
                  label, "disable-main", label
              )
          else:
              assert method == "observe", method
              baseline = settle_foreground(baseline_label, "full", "baseline")
              candidate, selected = foreground_activation(label, "full", label)

          foreign_cell = (
              "foreground-process/aos.foreground-process/abi-1/"
              f"{method}/reject-foreign-resource-mutation"
          )
          PROVIDER_FLIGHT.run_provider_flight(
              PROVIDER_FLIGHT.ProviderFlight(
                  adapter="foreground-process",
                  interface="aos.foreground-process",
                  method=method,
                  provider_key="shared-service",
                  resource_key="nginx-main-service",
                  label=label,
                  observation=matrix_cells[foreign_cell]["effect_class"]
                  == "observation",
                  mapping=resource_map(baseline, selected),
              ),
              candidate,
              PROVIDER_BUILDER,
              observe_sentinel=observe_secondary_foreground,
          )
    '';
  }
