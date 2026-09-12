##! Provider-negative qualification flights for production PostgreSQL clusters.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  providerNegative = import ../abilities/provider-negative-transition.nix {inherit lib;};
  fixture = import ./_postgresql-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    transitionTransform = providerNegative;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-provider-negative-cells.nix {inherit lib matrix;};
in
  import ./_ability-provider-negative-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-provider-negative-postgresql";
    qualifiedCells = cells.groups.postgresql;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_postgresql_packages()
      primary_database = "matrix_primary"
      primary_role = "matrix_primary_role"
      secondary_database = "matrix_secondary"
      secondary_role = "matrix_secondary_role"
      sentinel_database = "zz_foreign"
      sentinel_role = "zz_foreign_role"
      stable_version = "sha256:" + "51" * 32
      changed_version = "sha256:" + "52" * 32
      sentinel_version = "sha256:" + "61" * 32


      def activation(label, include_pair, version, lifecycle="full"):
          output = f"/var/lib/aos/ability-provider-negative/postgresql-{label}"
          authority = f"/var/lib/aos/ability-provider-negative/pg-authority-{label}"
          additional = []
          if include_pair:
              additional = [
                  (primary_database, primary_role, version, f"primary-{version[-8:]}"),
                  (secondary_database, secondary_role, version, f"secondary-{version[-8:]}")
              ]
          selected = generate_postgresql_activation(
              output,
              sentinel_database,
              sentinel_role,
              sentinel_version,
              "sentinel-stable",
              authority,
              lifecycle=lifecycle,
              additional=additional,
          )
          provision_postgresql_authority(selected, authority)
          host = f"/var/lib/aos/ability-provider-negative/pg-host-{label}.nix"
          write_postgresql_host(host, selected, extra_module=OBSERVER_HOST_MODULE)
          return host, selected


      def settle(label, include_pair, version):
          host, selected = activation(label, include_pair, version)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/provider-negative-pg-{shlex.quote(label)}",
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
      methods = sorted({cell_id.split("/")[3] for cell_id in COHORT_CELLS})
      for index, method in enumerate(methods):
          label = f"postgresql-{index:03d}"
          if method in {"materialize", "start"}:
              baseline = settle(f"{label}-baseline", False, stable_version)
              candidate, selected = activation(label, True, stable_version)
          elif method == "stop":
              baseline = settle(f"{label}-baseline", True, stable_version)
              candidate, selected = activation(label, True, stable_version, "remove")
          elif method == "restart":
              baseline = settle(f"{label}-baseline", True, stable_version)
              candidate, selected = activation(label, True, changed_version)
          else:
              assert method == "observe", method
              baseline = settle(f"{label}-baseline", True, stable_version)
              candidate, selected = activation(label, True, stable_version)

          foreign_cell = (
              "postgresql/aos.postgresql-effects/abi-1/"
              f"{method}/reject-foreign-resource-mutation"
          )
          PROVIDER_FLIGHT.run_provider_flight(
              PROVIDER_FLIGHT.ProviderFlight(
                  adapter="postgresql",
                  interface="aos.postgresql-effects",
                  method=method,
                  provider_key="postgresql",
                  resource_key=f"{primary_database}-postgresql",
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
