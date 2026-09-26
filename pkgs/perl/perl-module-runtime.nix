##! perl-module-runtime — Runtime module handling for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "0.016";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-module-runtime";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Module::Runtime returns Qualification/Example.pm.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Module::Runtime qw(module_notional_filename);\ndie \"wrong filename\" unless module_notional_filename(\"Qualification::Example\") eq \"Qualification/Example.pm\";\n";
        };
        "input" = "The valid module name Qualification::Example.";
        "operation" = "Convert the name to its notional module filename.";
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
        "expected" = "Module::Runtime rejects the invalid module name.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Module::Runtime qw(check_module_name);\neval { check_module_name(\"Qualification::../Invalid\") };\ndie \"invalid module name accepted\" unless $@ =~ /not a module name/;\n";
        };
        "input" = "A module name containing a path traversal segment.";
        "operation" = "Validate and convert the malformed module name.";
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
      urls = ["https://cpan.metacpan.org/authors/id/Z/ZE/ZEFRAM/Module-Runtime-${version}.tar.gz"];
      hash = "sha256-aDAuxkaDNUfUEL4o4JZ223UAb0qlihHzvbRP/pnw8CQ=";
    };
    sourceRoot = "Module-Runtime-${version}";
    module = "Module::Runtime";
    description = "Handles Perl modules at runtime";
    homepage = "https://metacpan.org/dist/Module-Runtime";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
