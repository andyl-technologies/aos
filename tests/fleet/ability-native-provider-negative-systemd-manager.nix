##! Provider-negative qualification flights for the built-in systemd manager.
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
  cells = import ./_ability-provider-negative-cells.nix {inherit lib matrix;};
in
  import ./_ability-provider-negative-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-negative-systemd-manager";
    qualifiedCells = cells.groups.systemd-manager;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_reference_packages()


      def activation(label, method=None, revision=None):
          output = f"/var/lib/aos/ability-provider-negative/activation-{label}"
          authority = f"/var/lib/aos/ability-provider-negative/authority-{label}"
          selected = generate_activation_fixture(
              output,
              label,
              label,
              authority,
              systemd_manager_method=method,
              systemd_manager_revision=revision,
          )
          provision_operator_authority(selected, authority)
          host = f"/var/lib/aos/ability-provider-negative/host-{label}.nix"
          write_activation_host(host, selected, OBSERVER_HOST_MODULE)
          return host, selected


      baseline, _ = activation("systemd-manager-baseline")
      runtime.succeed(
          f"{APM} switch --from {shlex.quote(baseline)} "
          "--eval-root /run/provider-negative-systemd-manager-baseline",
          timeout=1200,
      )
      matrix_cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      methods = sorted({
          cell_id.split("/")[3]
          for cell_id in COHORT_CELLS
      })
      for index, method in enumerate(methods):
          label = f"systemd-manager-{index:03d}"
          candidate, selected = activation(label, method, f"matrix-{index:03d}")
          foreign_cell = (
              "systemd-manager/aos.systemd-manager/abi-1/"
              f"{method}/reject-foreign-resource-mutation"
          )
          PROVIDER_FLIGHT.run_provider_flight(
              PROVIDER_FLIGHT.ProviderFlight(
                  adapter="systemd-manager",
                  interface="aos.systemd-manager",
                  method=method,
                  provider_key="matrix-systemd",
                  resource_key="aos-matrix-primary-service",
                  label=label,
                  observation=matrix_cells[foreign_cell]["effect_class"]
                  == "observation",
                  mapping=selected["native_resource_map"],
              ),
              candidate,
              PROVIDER_BUILDER,
          )
    '';
  }
