# One genuine performance-case VM sample; full scaling remains independent.
{
  pkgs,
  lib,
  sampleId,
  revision,
}: let
  vm = import ./phase7-qemu-hot-fork-scaling-vm.nix {
    inherit pkgs lib;
    performanceSample = {
      id = sampleId;
      inherit revision;
    };
    attrPath = "campaign-performance-paired-sample";
  };
  comparison = builtins.path {
    path = ./campaign-performance-comparison.py;
    name = "campaign-performance-comparison.py";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-campaign-performance-sample";
    version = "2";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.python3 vm];
    phases = [
      {
        name = "retain-actual-sample";
        script = ''
          set -eu
          test "$(sed -n '1p' ${vm}/result)" = PASS
          mkdir -p "$out"
          cp ${vm}/result ${vm}/serial.log ${vm}/host-reference.env "$out/"
          ${pkgs.python3}/bin/python3 - ${comparison} "$out" <<'PY'
          import pathlib
          import runpy
          import sys

          validator = runpy.run_path(sys.argv[1])
          output = pathlib.Path(sys.argv[2])
          serial = validator["bounded_read"](output / "serial.log").decode()
          provenance = validator["one_record"](
              serial, "campaign_performance_provenance_json",
              validator["MAX_SOURCE_MANIFEST_BYTES"],
          )
          validator["decode_json"](provenance)
          (output / "performance-source-manifest.json").write_bytes(provenance)
          report = validator["completed_measurements"](serial)
          sample_id = validator["one_record"](report, "campaign_performance_sample_id").decode()
          if sample_id != validator["decode_json"](provenance)["sample_id"]:
              raise ValueError("actual frame sample identity differs from VM provenance")
          for index in range(3):
              work = validator["one_record"](report, f"corpus_{index}_campaign_work_json")
              validator["decode_json"](work)
              (output / f"corpus-{index}-work.json").write_bytes(work)
          PY
        '';
      }
    ];
  }
