# Authenticates the RFC 10.4 host-time ratio and million-admission evidence.
{
  pkgs,
  nativeScaling,
  metadataMillion,
  attrPath ? "checks.crucible.phase9.gates.campaignPerformance",
}: let
  validator = builtins.path {
    path = ./campaign-performance-comparison.py;
    name = "campaign-performance-comparison.py";
  };
  currentSource = import ./_campaign-performance-provenance.nix {
    inherit pkgs;
    revision = "unmeasured-current-consumer";
    sampleId = null;
  };
  currentSourceFile = pkgs.writeTextFile {
    name = "campaign-performance-current-source.json";
    text = currentSource.text;
  };
  referenceComparisonFile = ./fixtures + "/campaign-performance-reference-comparison-v2.json";
  # Only a reviewed actual paired collection may populate this hash.
  referenceComparisonSha256 = null;
  approvedComparisonFile =
    if referenceComparisonSha256 != null && builtins.pathExists referenceComparisonFile
    then
      if builtins.hashFile "sha256" referenceComparisonFile == referenceComparisonSha256
      then referenceComparisonFile
      else throw "campaign performance v2 comparison hash mismatch"
    else null;
  decisionPlanFile = ./fixtures + "/campaign-performance-decision-v2.json";
  # The method, affected paths and source scope are fixed before data.
  decisionPlanSha256 = null;
  approvedDecisionFile =
    if decisionPlanSha256 != null && builtins.pathExists decisionPlanFile
    then
      if builtins.hashFile "sha256" decisionPlanFile == decisionPlanSha256
      then decisionPlanFile
      else throw "campaign performance v2 decision plan hash mismatch"
    else null;
  measuredSamples = import ./_campaign-performance-sample-closures.nix {
    comparisonFile = approvedComparisonFile;
    approvedSha256 =
      if approvedDecisionFile == null
      then null
      else referenceComparisonSha256;
  };
  measuredSampleManifest = pkgs.writeTextFile {
    name = "campaign-performance-measured-store-roots.json";
    text = builtins.toJSON measuredSamples;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-performance";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.python3 nativeScaling metadataMillion] ++ measuredSamples;
    runtimeDeps = measuredSamples;

    phases = [
      {
        name = "authenticate-performance-evidence";
        script = ''
          set -eu
          test "$(sed -n '1p' ${nativeScaling}/result)" = PASS
          test "$(sed -n '1p' ${metadataMillion}/result)" = PASS
          test -f ${nativeScaling}/serial.log
          test -f ${nativeScaling}/host-reference.env
          test -f ${metadataMillion}/evidence/profile.env

          mkdir -p "$out/evidence"
          cp ${nativeScaling}/serial.log "$out/evidence/scaling-serial.log"
          cp ${nativeScaling}/host-reference.env "$out/evidence/host-reference.env"
          cp ${
            let
              profile = ./fixtures/campaign-performance-reference-host-v1.env;
              approvedSha256 = "a02bc0b53272a4ac348c845887bcb8f515d7cd524aa681205cc2d85122c7bc7d";
            in
              if builtins.hashFile "sha256" profile == approvedSha256
              then profile
              else throw "campaign performance reference host profile hash mismatch"
          } "$out/evidence/reference-host-profile.env"
          cp ${metadataMillion}/evidence/profile.env "$out/evidence/million-profile.env"
          cp ${metadataMillion}/result "$out/evidence/metadata.result"
          reference_comparison='${
            if approvedComparisonFile == null
            then ""
            else builtins.toString approvedComparisonFile
          }'
          decision_plan='${
            if approvedDecisionFile == null
            then ""
            else builtins.toString approvedDecisionFile
          }'
          reference_sha=$(sha256sum "$out/evidence/reference-host-profile.env" | cut -d ' ' -f 1)

          ${pkgs.python3}/bin/python3 - \
            "$out/evidence/scaling-serial.log" \
            "$out/evidence/host-reference.env" \
            "$out/evidence/million-profile.env" \
            "$out/evidence/reference-host-profile.env" \
            "$reference_sha" ${validator} <<'PY'
          import pathlib
          import re
          import runpy
          import sys

          raw_serial, host, profile, reference = (pathlib.Path(arg).read_text() for arg in sys.argv[1:5])
          validator = runpy.run_path(sys.argv[6])
          serial = validator["completed_measurements"](raw_serial)
          one_number = validator["one_number"]

          def fields(text):
              lines = text.splitlines()
              assert all("=" in line for line in lines), lines
              pairs = [line.split("=", 1) for line in lines]
              assert len(pairs) == len({key for key, _ in pairs}), pairs
              return dict(pairs)

          expected = fields(reference)
          observed = fields(host)
          reference_sha = sys.argv[5]
          reference_keys = {
              "schema", "host_name", "host_cpu_model", "host_cpu_family",
              "host_cpu_model_number", "host_cpu_stepping", "host_cpu_microcode",
              "host_kernel_release", "host_pinned_cpu",
          }
          assert set(expected) == reference_keys, expected
          assert expected["schema"] == "crucible.campaign-performance.reference-host.v1"
          for key in reference_keys - {"schema"}:
              assert observed.get(key) == expected[key], (key, observed.get(key), expected[key])

          assert re.search(r"^campaign_guest_cpu_affinity=0$", serial, re.MULTILINE)
          assert re.search(r"^campaign_planner_supervisor=packaged-process$", serial, re.MULTILINE)
          assert re.search(r"^campaign_blob_backend=sqlite-store-graph$", serial, re.MULTILINE)
          assert re.search(r"^campaign_short_branch_boundary=two-node-pending-selectable$", serial, re.MULTILINE)
          assert expected["host_pinned_cpu"] == "0"
          assert re.search(r"^host_allowed_cpus=[0-9,-]+$", host, re.MULTILINE)
          assert re.search(r"^host_boot_id=[0-9a-f-]{36}$", host, re.MULTILINE)

          planner = sum(one_number(serial, f"corpus_{index}_campaign_planner_queue_ns") for index in range(3))
          guest = sum(one_number(serial, f"corpus_{index}_hot_guest_continuation_ns") for index in range(3))
          assert planner <= 2**64 - 1 and guest <= 2**64 - 1
          assert planner == one_number(serial, "campaign_planner_queue_total_ns")
          assert guest == one_number(serial, "hot_guest_continuation_total_ns")
          assert planner * 100 < guest * 5, (planner, guest)

          assert re.search(r"^campaign_million_profile admissions=1000000 requests=62500 request_size=16 ", profile)
          def profile_number(name):
              values = re.findall(rf"(?<!\S){re.escape(name)}=([0-9]+)(?=\s|$)", profile)
              assert len(values) == 1, (name, values)
              value = int(values[0])
              assert 0 < value <= 2**64 - 1, (name, value)
              return value

          for field in ("objects", "index_bytes", "logical_bytes", "physical_bytes", "cold_claimable"):
              profile_number(field)
          coordinator_rss = profile_number("coordinator_peak_rss_kib")
          worker_rss = profile_number("planner_worker_peak_rss_kib")
          combined_rss = profile_number("combined_peak_rss_upper_bound_kib")
          assert combined_rss == coordinator_rss + worker_rss
          assert combined_rss <= 4 * 1024 * 1024
          PY

          serial_sha=$(sha256sum "$out/evidence/scaling-serial.log" | cut -d ' ' -f 1)
          host_sha=$(sha256sum "$out/evidence/host-reference.env" | cut -d ' ' -f 1)
          profile_sha=$(sha256sum "$out/evidence/million-profile.env" | cut -d ' ' -f 1)
          if [ -z "$reference_comparison" ] || [ -z "$decision_plan" ]; then
            # A ratio-only v1 fixture cannot certify absolute equal-work timing.
            # Retain actual scaling/million evidence while paired data is absent.
            cat > "$out/result" <<RESULT
          BLOCKED
          gate=gate:campaign-performance
          check=${attrPath}
          reason=versioned-paired-reference-comparison-unmeasured
          reference_host_profile_sha256=$reference_sha
          serial_sha256=$serial_sha
          million_profile_sha256=$profile_sha
          RESULT
            exit 0
          fi
          cp ${measuredSampleManifest} "$out/evidence/measured-store-roots.json"
          cp "$reference_comparison" "$out/evidence/reference-comparison.json"
          cp "$decision_plan" "$out/evidence/decision-plan.json"
          cp ${currentSourceFile} "$out/evidence/current-source-manifest.json"
          ${pkgs.python3}/bin/python3 ${validator} \
            "$reference_comparison" "$decision_plan" \
            "$out/evidence/reference-host-profile.env" \
            --current-source "$out/evidence/current-source-manifest.json" \
            --current-serial "$out/evidence/scaling-serial.log" \
            > "$out/evidence/paired-decision.json"
          comparison_sha=$(sha256sum "$reference_comparison" | cut -d ' ' -f 1)
          decision_sha=$(sha256sum "$decision_plan" | cut -d ' ' -f 1)
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-performance
          check=${attrPath}
          task=T-CAM-9.2
          real_admissions=1000000
          short_branch_planner_queue_under_5_percent=true
          same_pinned_host_reference=true
          reference_host_profile_schema=crucible.campaign-performance.reference-host.v1
          reference_host_profile_sha256=$reference_sha
          paired_comparison_schema=crucible.campaign-performance.comparison.v2
          paired_comparison_sha256=$comparison_sha
          predeclared_decision_plan_sha256=$decision_sha
          required_absolute_timing_decision=per-metric-exact-paired-median-and-marginal-upper-at-most-one
          uncertainty_scope=marginal-stationary-pairs-no-universal-guarantee
          durable_metadata_budget_authenticated=true
          serial_sha256=$serial_sha
          host_reference_sha256=$host_sha
          million_profile_sha256=$profile_sha
          RESULT
        '';
      }
    ];
  }
