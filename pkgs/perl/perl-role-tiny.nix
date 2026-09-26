##! perl-role-tiny — Minimal role composition for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.002004";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-role-tiny";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Role::Tiny composes the method and it returns qualified.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\n{ package Qualified::Role; use Role::Tiny; requires \"name\"; sub label { shift->name } }\n{ package Qualified::Class; sub name { \"qualified\" } }\nRole::Tiny->apply_role_to_package(\"Qualified::Class\", \"Qualified::Role\");\ndie \"role method unavailable\" unless Qualified::Class->label eq \"qualified\";\n";
        };
        "input" = "A role requiring name and providing a label method, plus a class implementing name.";
        "operation" = "Apply the role to the class and call the provided method.";
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
        "expected" = "Role::Tiny rejects composition and identifies the missing requirement.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\n{ package Qualified::Role; use Role::Tiny; requires \"required_method\"; }\n{ package Qualified::Incomplete; }\neval { Role::Tiny->apply_role_to_package(\"Qualified::Incomplete\", \"Qualified::Role\") };\ndie \"unsatisfied role accepted\" unless $@ =~ /required_method/;\n";
        };
        "input" = "A class that lacks a method required by the role.";
        "operation" = "Apply the role to the incomplete class.";
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
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Role-Tiny-${version}.tar.gz"];
      hash = "sha256-173unhOKT4OqUtCpgWJWRL2of/FmQt+oRdy0TZokK0U=";
    };
    sourceRoot = "Role-Tiny-${version}";
    module = "Role::Tiny";
    description = "Provides lightweight role composition for Perl";
    homepage = "https://metacpan.org/dist/Role-Tiny";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
