##! perl-sub-quote — Efficient string-generated Perl subroutines
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.006008";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-sub-quote";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The generated subroutine returns 42 for inputs 19 and 23.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings; use Sub::Quote qw(quote_sub);\nmy $sum = quote_sub(\"Qualified::sum\", q{$_[0] + $_[1]});\ndie \"quoted subroutine failed\" unless $sum->(19, 23) == 42;\n";
        };
        "input" = "The Perl expression adding its first two arguments.";
        "operation" = "Compile the expression into a named subroutine with Sub::Quote and invoke it.";
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
        "expected" = "Sub::Quote rejects the malformed generated source.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings; use Sub::Quote qw(quote_sub);\neval { my $sub = quote_sub(\"Qualified::invalid\", q{this is !!!}); $sub->() };\ndie \"invalid generated source accepted\" unless $@;\n";
        };
        "input" = "A generated subroutine body containing invalid Perl syntax.";
        "operation" = "Compile and invoke the malformed body through Sub::Quote.";
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
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Sub-Quote-${version}.tar.gz"];
      hash = "sha256-lL69UAr1V2LoPqLyvFlNh6+CgHI3DHEQxgwjioANFbI=";
    };
    sourceRoot = "Sub-Quote-${version}";
    module = "Sub::Quote";
    description = "Generates Perl subroutines efficiently from strings";
    homepage = "https://metacpan.org/dist/Sub-Quote";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
