##! perl-parallel-forkmanager — Simple parallel processing for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-moo,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.02";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "perl-parallel-forkmanager";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Both child processes finish and both completion files contain their task number.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings; use Parallel::ForkManager;\nmy $manager = Parallel::ForkManager->new(2);\nfor my $number (1, 2) {\n    next if $manager->start($number);\n    open my $output, \">\", \"child-$number\" or die \"cannot create child result\";\n    print {$output} $number;\n    close $output;\n    $manager->finish(0);\n}\n$manager->wait_all_children;\nfor my $number (1, 2) {\n    open my $input, \"<\", \"child-$number\" or die \"child result missing\";\n    local $/; die \"wrong child result\" unless <$input> eq \"$number\";\n}\n";
        };
        "input" = "Two independent child tasks writing distinct completion files.";
        "operation" = "Run both tasks through Parallel::ForkManager and wait for them.";
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
        "expected" = "Parallel::ForkManager rejects the missing directory.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings; use Parallel::ForkManager;\neval { Parallel::ForkManager->new(2, \"qualification-missing-directory\") };\ndie \"missing temporary directory accepted\" unless $@ =~ /doesn't exist/;\n";
        };
        "input" = "A temporary directory path that does not exist.";
        "operation" = "Construct a fork manager using the invalid state directory.";
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
      urls = ["https://cpan.metacpan.org/authors/id/Y/YA/YANICK/Parallel-ForkManager-${version}.tar.gz"];
      hash = "sha256-wbKXCou2ZsPefKrEqPTbzAQ6uBm7wzdpLse/J62uRAQ=";
    };
    sourceRoot = "Parallel-ForkManager-${version}";
    module = "Parallel::ForkManager";
    # Perl does not discover propagated module directories on its own, so the
    # complete Moo module closure is explicit in PERL5LIB and the output graph.
    dependencies = [
      perl-class-method-modifiers
      perl-module-runtime
      perl-moo
      perl-role-tiny
      perl-sub-quote
    ];
    description = "Manages simple parallel processing with forked Perl processes";
    homepage = "https://metacpan.org/dist/Parallel-ForkManager";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
