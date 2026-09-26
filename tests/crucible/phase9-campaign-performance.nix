# Authenticates the RFC 10.4 host-time ratio and million-admission evidence.
{
  pkgs,
  nativeScaling,
  metadataMillion,
  attrPath ? "checks.crucible.phase9.gates.campaignPerformance",
}:
pkgs.mkDerivation {
  pname = "crucible-phase9-campaign-performance";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.python3 nativeScaling metadataMillion];

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
        reference_baseline='${
          let
            baseline = ./fixtures + "/campaign-performance-reference-baseline-v1.env";
            # A reviewed measured baseline commit must supply its pinned hash.
            approvedSha256 = null;
          in
            if builtins.pathExists baseline && approvedSha256 != null
            then
              if builtins.hashFile "sha256" baseline == approvedSha256
              then builtins.toString baseline
              else throw "campaign performance reference baseline hash mismatch"
            else ""
        }'
        if [ -n "$reference_baseline" ]; then
          cp "$reference_baseline" "$out/evidence/reference-baseline.env"
        fi
        reference_sha=$(sha256sum "$out/evidence/reference-host-profile.env" | cut -d ' ' -f 1)

        ${pkgs.python3}/bin/python3 - \
          "$out/evidence/scaling-serial.log" \
          "$out/evidence/host-reference.env" \
          "$out/evidence/million-profile.env" \
          "$out/evidence/reference-host-profile.env" \
          "$reference_sha" "$reference_baseline" <<'PY'
        import pathlib
        import re
        import sys

        serial, host, profile, reference = (pathlib.Path(arg).read_text() for arg in sys.argv[1:5])

        def fields(text):
            lines = text.splitlines()
            assert all("=" in line for line in lines), lines
            pairs = [line.split("=", 1) for line in lines]
            assert len(pairs) == len({key for key, _ in pairs}), pairs
            return dict(pairs)

        expected = fields(reference)
        observed = fields(host)
        reference_sha, baseline_path = sys.argv[5:]
        reference_keys = {
            "schema", "host_name", "host_cpu_model", "host_cpu_family",
            "host_cpu_model_number", "host_cpu_stepping", "host_cpu_microcode",
            "host_kernel_release", "host_pinned_cpu",
        }
        assert set(expected) == reference_keys, expected
        assert expected["schema"] == "crucible.campaign-performance.reference-host.v1"
        for key in reference_keys - {"schema"}:
            assert observed.get(key) == expected[key], (key, observed.get(key), expected[key])

        def one_number(text, name):
            values = re.findall(rf"^{re.escape(name)}=([0-9]+)$", text, re.MULTILINE)
            assert len(values) == 1, (name, values)
            value = int(values[0])
            assert 0 < value <= 2**64 - 1, (name, value)
            return value

        assert re.search(r"^campaign_guest_cpu_affinity=0$", serial, re.MULTILINE)
        assert re.search(r"^campaign_planner_supervisor=packaged-process$", serial, re.MULTILINE)
        assert re.search(r"^campaign_blob_backend=directory$", serial, re.MULTILINE)
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

        if baseline_path:
            baseline = fields(pathlib.Path(baseline_path).read_text())
            assert set(baseline) == {
                "schema", "reference_host_profile_sha256", "baseline_planner_queue_ns",
                "baseline_guest_continuation_ns", "max_planner_queue_ratio_ppm",
            }, baseline
            assert baseline["schema"] == "crucible.campaign-performance.baseline.v1"
            assert baseline["reference_host_profile_sha256"] == reference_sha
            baseline_planner = int(baseline["baseline_planner_queue_ns"])
            baseline_guest = int(baseline["baseline_guest_continuation_ns"])
            ratio_ceiling = int(baseline["max_planner_queue_ratio_ppm"])
            assert 0 < baseline_planner <= 2**64 - 1
            assert 0 < baseline_guest <= 2**64 - 1
            assert baseline_planner * 100 < baseline_guest * 5
            assert 0 < ratio_ceiling < 50_000
            assert baseline_planner * 1_000_000 <= baseline_guest * ratio_ceiling
            assert planner * 1_000_000 <= guest * ratio_ceiling, (planner, guest, ratio_ceiling)

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
        if [ -z "$reference_baseline" ]; then
          # Promote only a reviewed baseline populated from this exact-host raw
          # sample; its ratio ceiling then ratchets every later run.
          cat > "$out/result" <<RESULT
        BLOCKED
        gate=gate:campaign-performance
        check=${attrPath}
        reason=versioned-reference-baseline-unmeasured
        reference_host_profile_sha256=$reference_sha
        serial_sha256=$serial_sha
        million_profile_sha256=$profile_sha
        RESULT
          exit 0
        fi
        baseline_sha=$(sha256sum "$out/evidence/reference-baseline.env" | cut -d ' ' -f 1)
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
        reference_baseline_sha256=$baseline_sha
        durable_metadata_budget_authenticated=true
        serial_sha256=$serial_sha
        host_reference_sha256=$host_sha
        million_profile_sha256=$profile_sha
        RESULT
      '';
    }
  ];
}
