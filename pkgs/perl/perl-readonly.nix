##! perl-readonly — Read-only Perl values
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-readonly";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Readonly preserves the exact scalar value.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Readonly;\nReadonly my $value => \"qualified\";\ndie \"wrong readonly value\" unless $value eq \"qualified\";\n";
        };
        "input" = "A scalar initialized to the value qualified.";
        "operation" = "Declare it read-only and read the stored value.";
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
        "expected" = "Readonly rejects the assignment and preserves the original value.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Readonly;\nReadonly my $value => \"qualified\";\neval { $value = \"changed\"; };\ndie \"readonly assignment accepted\" unless $@ && $value eq \"qualified\";\n";
        };
        "input" = "An assignment that attempts to replace a read-only scalar.";
        "operation" = "Mutate the protected value.";
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
      urls = ["https://cpan.metacpan.org/authors/id/S/SA/SANKO/Readonly-${version}.tar.gz"];
      hash = "sha256-SyNUJJGvAQ1EpcfIYSRHOKzHSrq65riDjTVN+xlGK14=";
    };
    sourceRoot = "Readonly-${version}";
    module = "Readonly";
    description = "Creates read-only Perl scalars, arrays, and hashes";
    homepage = "https://metacpan.org/dist/Readonly";
    license = "Artistic-2.0";
  }
