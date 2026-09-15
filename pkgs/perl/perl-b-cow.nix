##! perl-b-cow — Copy-on-write inspection helpers for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "0.007";
  runtimeClosureManifest = builtins.toString perl;
in
  mkDerivation {
    pname = "perl-b-cow";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "B::COW reports support and a positive reference-count limit.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use B::COW qw(can_cow cowrefcnt_max);\ndie \"copy-on-write unavailable\" unless can_cow();\ndie \"invalid reference limit\" unless cowrefcnt_max() > 0;\n";
        };
        "input" = "A Perl string eligible for copy-on-write storage.";
        "operation" = "Inspect copy-on-write capability and its maximum reference count.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-b-cow operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-b-cow operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The module's Exporter contract rejects the unknown symbol.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\neval q{ use B::COW qw(qualification_invalid); 1 };\ndie \"invalid export accepted\" unless $@ =~ /not exported/;\n";
        };
        "input" = "An export name outside B::COW's documented API.";
        "operation" = "Import the unsupported symbol from B::COW.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-b-cow operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-b-cow operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/A/AT/ATOOMIC/B-COW-${version}.tar.gz"];
      hash = "sha256-EpDa8ifosJiJoxzxguKRBvHPnxpOm/d1L53pLtEVi0Q=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd B-COW-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${perl}/bin/perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make test'';
      }
      {
        name = "install";
        script = ''
          make install
          cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
          rm -f "$out"/lib/perl5/*/*/perllocal.pod "$out"/lib/perl5/*/*/.packlist

          # The XS module does not retain the interpreter used to load it.
          mkdir -p "$out/nix-support"
          echo '${runtimeClosureManifest}' > "$out/nix-support/runtime-closure"

          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MB::COW -e 1
        '';
      }
    ];

    meta = {
      description = "Copy-on-write inspection helpers for Perl internals";
      homepage = "https://metacpan.org/dist/B-COW";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
