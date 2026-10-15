# Requires complete measurements from the same actual normal service flight.
# The operational marker alone cannot satisfy this independent qualification.
{
  pkgs,
  operationalFlight,
  attrPath,
}:
pkgs.mkDerivation {
  pname = "crucible-normal-service-full-measurements";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed pkgs.jq];
  phases = [
    {
      name = "require-complete-physical-measurements";
      script = ''
        mkdir -p "$out"
        test "$(grep -Fc 'normal_service_physical_measurements=' ${operationalFlight}/result)" -eq 1
        sed -n 's/^normal_service_physical_measurements=//p' ${operationalFlight}/result > "$out/measurements.json"
        grep -E '^normal_service_build_graph=[0-9a-f]{64}$' ${operationalFlight}/result > "$out/artifact-provenance"
        grep -E '^normal_service_main_elf=/nix/store/[^/]+/bin/crucible$' ${operationalFlight}/result >> "$out/artifact-provenance"
        if ! jq -e '
          .target != null and (.observation_sequence | type == "number")
          and (.policy_revision | type == "number")
          and (.reservation_revision | type == "number")
          and .measurements_available == true
          and ([.private_resident_bytes, .shared_resident_bytes_observed,
            .preserved_backing_bytes, .private_dirty_bytes,
            .writeback_pending_bytes]
            | all(.[]; type == "number" and . >= 0))
        ' "$out/measurements.json" > /dev/null; then
          echo 'normal service complete physical measurements remain unqualified' >&2
          exit 1
        fi
        printf 'PASS\ncheck=%s\n' '${attrPath}' > "$out/result"
      '';
    }
  ];
}
