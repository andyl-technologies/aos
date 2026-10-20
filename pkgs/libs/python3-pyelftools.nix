##! python3-pyelftools — pure-Python ELF / DWARF parsing library
##!
##! Required by systemd-ukify and by systemd's meson configure probe
##! (which rejects the build if `import elftools` fails when
##! -Dukify=enabled). pyelftools has no external Python dependencies —
##! pure-Python walking of ELF section tables, DWARF debug info, and
##! the .note sections that sd-stub uses.
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "0.32";
  pyVersion = "3.14";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-pyelftools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "ELFFile recognizes a 32-bit or 64-bit executable container.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom elftools.elf.elffile import ELFFile\nwith open(sys.executable, \"rb\") as source:\n    parsed = ELFFile(source)\n    assert parsed.elfclass in (32, 64)\n\nprint(\"python3-pyelftools primary passed\")\n";
        };
        "input" = "The ELF executable produced from a minimal C translation unit.";
        "operation" = "Compile the program and parse its ELF header with pyelftools.";
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
              "exact" = "python3-pyelftools primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "pyelftools rejects the stream with ELFError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom elftools.common.exceptions import ELFError\nfrom elftools.elf.elffile import ELFFile\nwith open(\"not-elf\", \"wb\") as destination:\n    destination.write(b\"not an ELF file\")\ntry:\n    with open(\"not-elf\", \"rb\") as source:\n        ELFFile(source)\nexcept ELFError:\n    pass\nelse:\n    raise RuntimeError(\"pyelftools accepted non-ELF bytes\")\n\nprint(\"python3-pyelftools rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A plain-text file that lacks the ELF magic and header.";
        "operation" = "Construct ELFFile from the invalid bytes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-pyelftools rejected invalid input\n";
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
        "https://github.com/eliben/pyelftools/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-gtA5m8500WL7p1s1aK1Hv0jtLF4Ci3ICa9wvZ4kD3n0=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pyelftools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python${pyVersion}/site-packages
          mkdir -p "$site"
          cp -r elftools "$site/"
        '';
      }
    ];

    meta = {
      description = "pyelftools — pure-Python ELF/DWARF parser";
      homepage = "https://github.com/eliben/pyelftools";
      license = "Unlicense";
    };
  }
