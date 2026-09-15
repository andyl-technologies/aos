##! server-initrd-firmware — pre-root firmware for supported server adapters
{
  lib,
  mkDerivation,
  firmware,
}: let
  version = firmware.version;
in
  mkDerivation {
    pname = "server-initrd-firmware";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "All four server-adapter families contain nonempty files and are described by WHENCE.";
        "files" = {};
        "input" = "The bounded bnx2, bnx2x, cxgb4, and qed pre-root firmware families.";
        "operation" = "Walk each selected family and verify its firmware payload and WHENCE attribution.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nroot = pathlib.Path(\"@out@/lib/firmware\")\nattribution = (root / \"WHENCE\").read_text(errors=\"replace\").lower()\nfor family in [\"bnx2\", \"bnx2x\", \"cxgb4\", \"qed\"]:\n    directory = root / family\n    files = [path for path in directory.rglob(\"*\") if path.is_file()]\n    assert files and all(path.stat().st_size > 0 for path in files)\n    assert family in attribution\nprint(\"server-initrd-firmware operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "server-initrd-firmware operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The bounded server firmware package rejects the absent wireless family.";
        "files" = {};
        "input" = "A request for an unrelated desktop wireless firmware family.";
        "operation" = "Resolve the family outside the documented initrd subset.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib\nassert not pathlib.Path(\"@out@/lib/firmware/iwlwifi\").exists()\n\nsys.stderr.write(\"server-initrd-firmware rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "server-initrd-firmware rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    src = null;

    buildDeps = [firmware];
    runtimeDeps = [];
    propagatedDeps = [];

    passthru.evidenceSources = [./server-initrd-firmware.nix];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/firmware"

          # These families back storage and network adapters that can be
          # required for discovery, provisioning, or unlocking before the
          # immutable root is available. Other firmware stays in the runtime
          # image and can be selected explicitly for hardware-specific initrds.
          for family in bnx2 bnx2x cxgb4 qed; do
            cp -a "${firmware}/lib/firmware/$family" "$out/lib/firmware/"
          done
          cp -a ${firmware}/lib/firmware/WHENCE \
            ${firmware}/lib/firmware/LICENCE.* "$out/lib/firmware/"
        '';
      }
    ];

    meta = {
      description = "Firmware subset for server devices needed before switch-root";
      homepage = firmware.meta.homepage;
      license = firmware.meta.license;
    };
  }
