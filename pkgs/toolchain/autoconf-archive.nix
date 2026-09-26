##! autoconf-archive — Collection of reusable Autoconf macros
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2024.10.16";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "autoconf-archive";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The archive supplies a nonempty AX_PTHREAD definition that tests pthread_create.";
        "files" = {};
        "input" = "The installed AX_PTHREAD Autoconf macro.";
        "operation" = "Parse its public macro declaration and required pthread link probes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, re\nsource = pathlib.Path(\"@out@/share/aclocal/ax_pthread.m4\").read_text()\nassert re.search(r\"AC_DEFUN\\s*\\(\\s*\\[AX_PTHREAD\\]\", source)\nassert \"pthread_create\" in source\nprint(\"autoconf-archive data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "autoconf-archive data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The catalog lookup rejects the absent macro.";
        "files" = {};
        "input" = "A request for an AOS-specific macro that the archive does not define.";
        "operation" = "Search the installed macro catalog for that exact declaration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, re, sys\nfound = any(re.search(r\"AC_DEFUN\\s*\\(\\s*\\[AX_AOS_NONEXISTENT\\]\", path.read_text(errors=\"replace\")) for path in pathlib.Path(\"@out@/share/aclocal\").glob(\"*.m4\"))\nif found:\n    raise SystemExit(2)\nsys.stderr.write(\"autoconf-archive rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "autoconf-archive rejected invalid input\n";
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
      urls = ["https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-${version}.tar.xz"];
      hash = "sha256-e81dABkW86UO10NvT3AOPSsbrePtgDIZxZLWJQKlc2M=";
    };
    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd autoconf-archive-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -f "$out/share/aclocal/ax_pthread.m4"
        '';
      }
    ];
    meta = {
      description = "Provides reusable macros for GNU Autoconf";
      homepage = "https://www.gnu.org/software/autoconf-archive/";
      license = "GPL-3.0-only";
    };
  }
