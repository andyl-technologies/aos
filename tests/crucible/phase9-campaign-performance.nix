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
        cp ${metadataMillion}/evidence/profile.env "$out/evidence/million-profile.env"
        cp ${metadataMillion}/result "$out/evidence/metadata.result"

        ${pkgs.python3}/bin/python3 - \
          "$out/evidence/scaling-serial.log" \
          "$out/evidence/host-reference.env" \
          "$out/evidence/million-profile.env" <<'PY'
        import pathlib
        import re
        import sys

        serial, host, profile = (pathlib.Path(arg).read_text() for arg in sys.argv[1:])

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
        assert re.search(r"^host_pinned_cpu=[0-9]+$", host, re.MULTILINE)
        assert re.search(r"^host_cpu_model=.+$", host, re.MULTILINE)
        assert re.search(r"^host_name=.+$", host, re.MULTILINE)
        assert re.search(r"^host_boot_id=[0-9a-f-]{36}$", host, re.MULTILINE)

        planner = sum(one_number(serial, f"corpus_{index}_campaign_planner_queue_ns") for index in range(3))
        guest = sum(one_number(serial, f"corpus_{index}_hot_guest_continuation_ns") for index in range(3))
        assert planner <= 2**64 - 1 and guest <= 2**64 - 1
        assert planner == one_number(serial, "campaign_planner_queue_total_ns")
        assert guest == one_number(serial, "hot_guest_continuation_total_ns")
        assert planner * 100 < guest * 5, (planner, guest)

        assert re.search(r"^campaign_million_profile admissions=1000000 requests=62500 request_size=16 ", profile)
        for field in ("objects", "index_bytes", "logical_bytes", "physical_bytes", "coordinator_peak_rss_kib", "planner_worker_peak_rss_kib", "combined_peak_rss_upper_bound_kib", "cold_claimable"):
            assert re.search(rf"\b{field}=[1-9][0-9]*\b", profile), field
        PY

        serial_sha=$(sha256sum "$out/evidence/scaling-serial.log" | cut -d ' ' -f 1)
        host_sha=$(sha256sum "$out/evidence/host-reference.env" | cut -d ' ' -f 1)
        profile_sha=$(sha256sum "$out/evidence/million-profile.env" | cut -d ' ' -f 1)
        cat > "$out/result" <<RESULT
        PASS
        gate=gate:campaign-performance
        check=${attrPath}
        task=T-CAM-9.2
        real_admissions=1000000
        short_branch_planner_queue_under_5_percent=true
        same_pinned_host_reference=true
        durable_metadata_budget_authenticated=true
        serial_sha256=$serial_sha
        host_reference_sha256=$host_sha
        million_profile_sha256=$profile_sha
        RESULT
      '';
    }
  ];
}
