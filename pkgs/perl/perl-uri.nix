##! perl-uri — Uniform resource identifier support for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "5.21";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-uri";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The URI resolves to /a/qualified, lowercases the host, and retains the query.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use URI;\nmy $uri = URI->new_abs(\"../qualified?q=1\", \"HTTPS://Example.TEST/a/b/\")->canonical;\ndie \"wrong canonical URI\" unless $uri->as_string eq \"https://example.test/a/qualified?q=1\";\n";
        };
        "input" = "The relative URI ../qualified?q=1 and HTTPS base https://Example.TEST/a/b/.";
        "operation" = "Resolve and canonicalize the relative URI through the URI API.";
        "steps" = [
          {
            "argv" = [
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "URI rejects the missing base argument.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use URI;\neval { URI->new_abs(\"child\", undef) };\ndie \"missing base accepted\" unless $@ =~ /Missing base argument/;\n";
        };
        "input" = "A relative URI without the required base URI.";
        "operation" = "Resolve the relative URI through URI->new_abs.";
        "steps" = [
          {
            "argv" = [
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
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
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/URI-${version}.tar.gz"];
      hash = "sha256-liZYYM1hveFuhBXc+/EIBW3hYsqgrDf4HraVydLgq3c=";
    };
    sourceRoot = "URI-${version}";
    module = "URI";
    description = "Implements uniform resource identifiers in Perl";
    homepage = "https://metacpan.org/dist/URI";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
