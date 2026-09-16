##! perl-io-tty — Pseudo-terminal support for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "1.20";
  runtimeClosureManifest = builtins.toString perl;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-io-tty";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "IO::Pty returns a master and a slave with a nonempty terminal path.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::Pty;\nmy $master = IO::Pty->new;\nmy $slave = $master->slave;\ndie \"pseudo-terminal unavailable\" unless $master && $slave && $slave->ttyname;\n$slave->close; $master->close;\n";
        };
        "input" = "A request for a fresh pseudo-terminal pair.";
        "operation" = "Allocate the pair with IO::Pty and inspect the slave terminal name.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-io-tty operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-io-tty operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "IO::Tty declines the invalid descriptor.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::Tty;\nmy $tty = eval { IO::Tty->new_from_fd(-1, \"r\") };\ndie \"invalid descriptor accepted\" if defined $tty;\n";
        };
        "input" = "A pseudo-terminal request using invalid file descriptor -1.";
        "operation" = "Construct IO::Tty from the invalid descriptor.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-io-tty operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-io-tty operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TO/TODDR/IO-Tty-${version}.tar.gz"];
      hash = "sha256-sVMJ/IViOJMonLmyuI36ntHmkVa3XymThVOkW+bXMK8=";
    };
    buildDeps = [gnumake perl];
    runtimeDeps = [perl];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd IO-Tty-${version}
        '';
      }
      {
        name = "configure";
        script = ''${perl}/bin/perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"'';
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

          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MIO::Tty -e 1
        '';
      }
    ];
    meta = {
      description = "Low-level pseudo-terminal allocation and terminal constants for Perl";
      homepage = "https://metacpan.org/dist/IO-Tty";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
