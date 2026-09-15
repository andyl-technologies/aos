##! python3-pefile — pure-Python Portable Executable reader/writer
##!
##! Required by systemd-ukify (systemd's UKI assembler) at runtime —
##! ukify imports pefile to append sections (.osrel, .cmdline, .linux,
##! .initrd) to the sd-stub PE-COFF binary. See pkgs/system/systemd.nix
##! for the wrap that puts this package on ukify's Python search path.
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "2024.8.26";
  # Hardcoded to match python3.nix's site-packages layout
  # (python3 exposes 3.14; adjust here if python3.nix is bumped).
  pyVersion = "3.14";
in
  mkDerivation {
    pname = "python3-pefile";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parsed file and optional headers expose the encoded values.";
        "files" = {
          "probe.py" = "import glob\nimport struct\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport pefile\n\nimage = bytearray(0x178)\nimage[0:2] = b\"MZ\"\nstruct.pack_into(\"<I\", image, 0x3C, 0x80)\nimage[0x80:0x84] = b\"PE\\0\\0\"\nstruct.pack_into(\"<HHIIIHH\", image, 0x84, 0x14C, 0, 0, 0, 0, 0xE0, 0x0102)\n\noptional = 0x98\nstruct.pack_into(\"<H\", image, optional, 0x10B)\nstruct.pack_into(\"<I\", image, optional + 16, 0x1000)\nstruct.pack_into(\"<I\", image, optional + 28, 0x400000)\nstruct.pack_into(\"<I\", image, optional + 32, 0x1000)\nstruct.pack_into(\"<I\", image, optional + 36, 0x200)\nstruct.pack_into(\"<I\", image, optional + 56, 0x1000)\nstruct.pack_into(\"<I\", image, optional + 60, 0x200)\nstruct.pack_into(\"<H\", image, optional + 68, 3)\nstruct.pack_into(\"<I\", image, optional + 92, 16)\n\nparsed = pefile.PE(data=bytes(image), fast_load=False)\nassert parsed.FILE_HEADER.Machine == 0x14C\nassert parsed.OPTIONAL_HEADER.ImageBase == 0x400000\nassert len(parsed.sections) == 0\nprint(\"python3-pefile primary passed\")\n";
        };
        "input" = "A minimal PE32 image with an i386 machine header and image base 0x400000.";
        "operation" = "Construct and parse the image through pefile.PE.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "python3-pefile primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Pefile raises PEFormatError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport pefile\n\ntry:\n    pefile.PE(data=b\"not a portable executable\")\nexcept pefile.PEFormatError:\n    print(\"python3-pefile rejected invalid input\", file=sys.stderr)\n    raise SystemExit(7)\nraise RuntimeError(\"pefile accepted malformed input\")\n";
        };
        "input" = "Bytes that contain neither a DOS header nor a PE header.";
        "operation" = "Parse the malformed image through pefile.PE.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-pefile rejected invalid input\n";
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
        "https://github.com/erocarrera/pefile/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-EW7Cm2iepPDt5zJ+u9eUzol35eqpdWU5NEHTQE3uzaM=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pefile-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python${pyVersion}/site-packages
          mkdir -p "$site"
          cp pefile.py peutils.py "$site/"
          cp -r ordlookup "$site/"
        '';
      }
    ];

    meta = {
      description = "pefile — pure-Python Portable Executable reader/writer";
      homepage = "https://github.com/erocarrera/pefile";
      license = "MIT";
    };
  }
