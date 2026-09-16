##! perl-mozilla-ca — CA certificate bundle interface for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  ca-certificates,
}: let
  version = "20230821";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-mozilla-ca";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns an existing file beginning with a certificate PEM block.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Mozilla::CA;\nmy $path = Mozilla::CA::SSL_ca_file();\nopen my $input, \"<\", $path or die \"cannot open CA bundle\";\nlocal $/; my $bundle = <$input>;\ndie \"invalid CA bundle\" unless $bundle =~ /-----BEGIN CERTIFICATE-----/;\n";
        };
        "input" = "A request for the packaged Mozilla certificate bundle.";
        "operation" = "Resolve the bundle through Mozilla::CA and inspect its PEM boundary.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-mozilla-ca operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-mozilla-ca operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Perl rejects the method because Mozilla::CA exposes only SSL_ca_file.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Mozilla::CA;\neval { Mozilla::CA->qualification_invalid_bundle() };\ndie \"unsupported bundle selector accepted\" unless $@ =~ /Can't locate object method/;\n";
        };
        "input" = "A request for an unsupported named certificate bundle API.";
        "operation" = "Dispatch the nonexistent bundle selector on Mozilla::CA.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-mozilla-ca operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-mozilla-ca operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-${version}.tar.gz"];
      hash = "sha256-MuHQBFKZAEBFucTRbC2q5FOiFiCIc97qJED3EmCnzaE=";
    };
    sourceRoot = "Mozilla-CA-${version}";
    module = "Mozilla::CA";
    dependencies = [ca-certificates];
    postInstall = ''
      rm -f "$out/lib/perl5/Mozilla/CA/cacert.pem"
      ln -s ${ca-certificates}/etc/ssl/certs/ca-certificates.crt \
        "$out/lib/perl5/Mozilla/CA/cacert.pem"
    '';
    description = "Exposes the system CA certificate bundle to Perl";
    homepage = "https://metacpan.org/dist/Mozilla-CA";
    license = "MPL-2.0";
  }
