##! perl-clone — Recursive Perl data cloning
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  perl-b-cow,
}: let
  version = "0.46";
  runtimeClosureManifest = builtins.toString perl;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-clone";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The clone is independent and the source array remains unchanged.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Clone qw(clone);\nmy $source = { values => [1, 2] };\nmy $copy = clone($source);\npush @{$copy->{values}}, 3;\ndie \"clone shares nested storage\" unless @{$source->{values}} == 2 && @{$copy->{values}} == 3;\n";
        };
        "input" = "A nested hash containing an array reference.";
        "operation" = "Deep-clone the structure and mutate only the clone.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-clone operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-clone operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Clone rejects the call for having too few arguments.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Clone qw(clone);\neval q{ clone() };\ndie \"missing input accepted\" unless $@ =~ /Not enough arguments/;\n";
        };
        "input" = "A clone request with its required scalar argument omitted.";
        "operation" = "Invoke Clone::clone without an input value.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-clone operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-clone operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GARU/Clone-${version}.tar.gz"];
      hash = "sha256-qt7tXkyL1rvfaMDdAGbLUT4Wq55bQ4LcSgqv1ViQaXs=";
    };

    buildDeps = [gnumake perl perl-b-cow];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd Clone-${version}
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
        script = ''PERL5LIB=${perl-b-cow}/lib/perl5 make test'';
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

          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MClone -e 1
        '';
      }
    ];

    meta = {
      description = "Recursively copies Perl data structures";
      homepage = "https://metacpan.org/dist/Clone";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
