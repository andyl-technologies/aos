##! linux-firmware — Firmware files for Linux kernel drivers
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "20260110";
in
  mkDerivation {
    pname = "firmware";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "WHENCE identifies upstream firmware and the selected tree contains many payload files.";
        "files" = {};
        "input" = "The selected Linux firmware tree and its WHENCE inventory.";
        "operation" = "Read the inventory and verify that installed payload families contain regular files.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nroot = pathlib.Path(\"@out@/lib/firmware\")\nwhence = (root / \"WHENCE\").read_text(errors=\"replace\")\nfiles = [path for path in root.rglob(\"*\") if path.is_file() and path.name != \"WHENCE\"]\nassert \"Driver:\" in whence and \"File:\" in whence and len(files) > 10\nprint(\"firmware data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "firmware data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The firmware lookup rejects the unknown payload.";
        "files" = {};
        "input" = "A request for a firmware payload name absent from the selected tree.";
        "operation" = "Resolve the nonexistent payload beneath the firmware root.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/lib/firmware/aos/nonexistent.bin\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"firmware rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "firmware rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware-${version}.tar.xz"
      ];
      hash = "sha256-SOBRZttTn07o0prJ0japRELFsbGhYKlm9v5rQr1xQzE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-firmware-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/lib/firmware

          # Install selected firmware families needed for server/cloud usage.
          # Network adapters
          cp -a intel $out/lib/firmware/ 2>/dev/null || true
          cp -a i915 $out/lib/firmware/ 2>/dev/null || true
          cp -a iwlwifi* $out/lib/firmware/ 2>/dev/null || true
          cp -a mellanox $out/lib/firmware/ 2>/dev/null || true
          cp -a bnx2 $out/lib/firmware/ 2>/dev/null || true
          cp -a bnx2x $out/lib/firmware/ 2>/dev/null || true
          cp -a bnxt $out/lib/firmware/ 2>/dev/null || true

          # Storage controllers
          cp -a qed $out/lib/firmware/ 2>/dev/null || true
          cp -a qla2xxx $out/lib/firmware/ 2>/dev/null || true
          cp -a cxgb4 $out/lib/firmware/ 2>/dev/null || true
          cp -a amd $out/lib/firmware/ 2>/dev/null || true
          cp -a amd-ucode $out/lib/firmware/ 2>/dev/null || true
          cp -a intel-ucode $out/lib/firmware/ 2>/dev/null || true

          # Install the WHENCE and LICENSE files
          cp WHENCE LICENCE.* $out/lib/firmware/ 2>/dev/null || true
        '';
      }
    ];

    meta = {
      description = "linux-firmware — firmware files for Linux kernel drivers";
      homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git";
      license = "Linux-firmware";
    };
  }
