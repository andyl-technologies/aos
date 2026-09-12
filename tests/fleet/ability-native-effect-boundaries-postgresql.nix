##! Production interruption flights for the native PostgreSQL provider.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  effectBoundary = import ../abilities/effect-boundary-transition.nix {inherit lib;};
  providerNegative = import ../abilities/provider-negative-transition.nix {inherit lib;};
  fixture = import ./_postgresql-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    transitionTransform = transition: effectBoundary (providerNegative transition);
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  cells = import ./_ability-effect-boundary-cells.nix {
    inherit lib matrix;
  };
in
  import ./_ability-effect-boundary-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-effect-boundaries-postgresql";
    qualifiedCells = cells.groups.postgresql;
    domainScript = ''
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )
      publish_postgresql_packages()

      target_database = "effect_app"
      target_role = "effect_role"
      foreign_database = "foreign_app"
      foreign_role = "foreign_role"
      stable_version = "sha256:" + "31" * 32
      changed_version = "sha256:" + "32" * 32
      foreign_version = "sha256:" + "41" * 32


      def postgresql_activation(label, include_target, target_version):
          output = f"/var/lib/aos/ability-boundary-test/postgresql-{label}"
          authority = f"/var/lib/aos/ability-boundary-test/pg-authority-{label}"
          additional = []
          if include_target:
              additional.append((
                  target_database,
                  target_role,
                  target_version,
                  f"target-{target_version[-8:]}",
              ))
          activation = generate_postgresql_activation(
              output,
              foreign_database,
              foreign_role,
              foreign_version,
              "foreign-stable",
              authority,
              additional=additional,
          )
          provision_postgresql_authority(activation, authority)
          host = f"/var/lib/aos/ability-boundary-test/pg-host-{label}.nix"
          write_postgresql_host(
              host, activation, extra_module=OBSERVER_HOST_MODULE
          )
          runtime.succeed(
              f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}"
          )
          return host


      def settle_postgresql(label, include_target, target_version):
          runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
          host = postgresql_activation(label, include_target, target_version)
          runtime.succeed(
              f"{APM} switch --from {shlex.quote(host)} "
              f"--eval-root /run/postgresql-effect-baseline-{shlex.quote(label)}",
              timeout=1200,
          )


      def replace_postgresql_foreign(value):
          if isinstance(value, str):
              return (
                  value.replace(target_database, foreign_database)
                  .replace(target_role, foreign_role)
              )
          if isinstance(value, list):
              return [replace_postgresql_foreign(child) for child in value]
          if isinstance(value, dict):
              return {
                  key: replace_postgresql_foreign(child)
                  for key, child in value.items()
              }
          return value


      for index, cell_id in enumerate(COHORT_CELLS):
          adapter, interface, _, method, _ = cell_id.split("/")
          assert adapter == "postgresql", cell_id
          label = f"postgresql-{index:03d}"
          baseline_label = f"{label}-baseline"

          if method in {"materialize", "start"}:
              settle_postgresql(baseline_label, False, stable_version)
              candidate = postgresql_activation(label, True, stable_version)
          elif method == "stop":
              settle_postgresql(baseline_label, True, stable_version)
              candidate = postgresql_activation(label, False, stable_version)
          elif method == "restart":
              settle_postgresql(baseline_label, True, stable_version)
              candidate = postgresql_activation(label, True, changed_version)
          else:
              assert method == "observe", method
              settle_postgresql(baseline_label, True, stable_version)
              candidate = postgresql_activation(label, True, stable_version)

          flight = EFFECT_FLIGHT.EffectFlight(
              cell_id=cell_id,
              interface=interface,
              method=method,
              provider_key="postgresql",
              resource_key=f"{target_database}-postgresql",
              label=label,
          )

          def observe_postgresql(operation, cell_id=cell_id):
              foreign = {
                  "adapter": "postgresql",
                  "operation": replace_postgresql_foreign(operation),
              }
              return EFFECT_ORACLES.observe_resource(
                  cell_id, operation, foreign
              )

          EFFECT_FLIGHT.run_effect_flight(
              flight, candidate, EFFECT_BUILDER, observe_postgresql
          )
    '';
  }
