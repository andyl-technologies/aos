##! Exercises Perl object, role, subprocess, and runtime helper module APIs.
{testing}: let
  perlDriver = package: ''
    import json, os, pathlib, subprocess

    closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
    interpreters = sorted({str(pathlib.Path(path) / "bin/perl") for path in closure if (pathlib.Path(path) / "bin/perl").is_file()})
    libraries = sorted(str(pathlib.Path(path) / "lib/perl5") for path in closure if (pathlib.Path(path) / "lib/perl5").is_dir())
    assert interpreters and libraries
    environment = os.environ.copy()
    environment["PERL5LIB"] = ":".join(libraries)
    result = subprocess.run([interpreters[0], "probe.pl"], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "" and result.stderr == ""
    print("${package} operation passed")
  '';

  # Sub::Quote 2.006008 triggers this warning on Perl 5.44 from a dead
  # Perl-5.10 compatibility branch. Ignore only that exact upstream warning.
  subQuoteWarningGuard = ''
    BEGIN {
        $SIG{__WARN__} = sub {
            my ($warning) = @_;
            die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\(\) list .*Sub\/Quote\.pm line 64/;
        };
    }
  '';

  mkPerlProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryProgram,
    badInput,
    badOperation,
    badExpected,
    badProgram,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files."probe.pl" = primaryProgram;
          steps = [
            {
              argv = ["@python@" "-c" (perlDriver package)];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files."probe.pl" = badProgram;
          steps = [
            {
              argv = ["@python@" "-c" (perlDriver package)];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  perl-class-method-modifiers = mkPerlProbe {
    package = "perl-class-method-modifiers";
    primaryInput = "A class method with an after modifier that records one invocation.";
    primaryOperation = "Install the modifier and call the method.";
    primaryExpected = "Class::Method::Modifiers preserves the return value and runs the modifier once.";
    primaryProgram = ''
      use strict; use warnings;
      { package Qualified::Class; sub value { "qualified" } }
      { package Qualified::Class; use Class::Method::Modifiers; our $calls = 0; after value => sub { $calls++ }; }
      die "method result changed" unless Qualified::Class->value eq "qualified";
      die "modifier did not run" unless $Qualified::Class::calls == 1;
    '';
    badInput = "A modifier targeting a method absent from the class.";
    badOperation = "Install an after modifier for the nonexistent method.";
    badExpected = "Class::Method::Modifiers rejects the missing target.";
    badProgram = ''
      use strict; use warnings; use Class::Method::Modifiers qw(install_modifier);
      { package Qualified::Empty; }
      eval { install_modifier("Qualified::Empty", "after", "qualification_missing", sub {}) };
      die "missing method accepted" unless $@;
    '';
  };

  perl-io-tty = mkPerlProbe {
    package = "perl-io-tty";
    primaryInput = "A request for a fresh pseudo-terminal pair.";
    primaryOperation = "Allocate the pair with IO::Pty and inspect the slave terminal name.";
    primaryExpected = "IO::Pty returns a master and a slave with a nonempty terminal path.";
    primaryProgram = ''
      use strict; use warnings; use IO::Pty;
      my $master = IO::Pty->new;
      my $slave = $master->slave;
      die "pseudo-terminal unavailable" unless $master && $slave && $slave->ttyname;
      $slave->close; $master->close;
    '';
    badInput = "A pseudo-terminal request using invalid file descriptor -1.";
    badOperation = "Construct IO::Tty from the invalid descriptor.";
    badExpected = "IO::Tty declines the invalid descriptor.";
    badProgram = ''
      use strict; use warnings; use IO::Tty;
      my $tty = eval { IO::Tty->new_from_fd(-1, "r") };
      die "invalid descriptor accepted" if defined $tty;
    '';
  };

  perl-ipc-run = mkPerlProbe {
    package = "perl-ipc-run";
    primaryInput = "A child Perl command that emits one fixed line.";
    primaryOperation = "Run the command and capture its standard output with IPC::Run.";
    primaryExpected = "IPC::Run reports success and captures the exact line.";
    primaryProgram = ''
      use strict; use warnings; use IPC::Run qw(run);
      my $output = "";
      my $ok = run([$^X, "-e", q{print "qualified\n"}], ">", \$output);
      die "child failed" unless $ok && $output eq "qualified\n";
    '';
    badInput = "A child executable name absent from the imported closure.";
    badOperation = "Start the nonexistent command through IPC::Run.";
    badExpected = "IPC::Run rejects the missing executable.";
    badProgram = ''
      use strict; use warnings; use IPC::Run qw(run);
      eval { run(["qualification-command-does-not-exist"]) };
      die "missing executable accepted" unless $@;
    '';
  };

  perl-moo = mkPerlProbe {
    package = "perl-moo";
    primaryInput = "A class with one required read-only name attribute.";
    primaryOperation = "Construct the object and call a method derived from the attribute.";
    primaryExpected = "Moo initializes the attribute and the method returns qualified.";
    primaryProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings;
      { package Qualified::Moo; use Moo; has name => (is => "ro", required => 1); sub label { shift->name } }
      my $object = Qualified::Moo->new(name => "qualified");
      die "wrong object value" unless $object->label eq "qualified";
    '';
    badInput = "An object construction request missing its required name attribute.";
    badOperation = "Construct the Moo class without the required value.";
    badExpected = "Moo rejects construction and names the missing attribute.";
    badProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings;
      { package Qualified::Moo; use Moo; has name => (is => "ro", required => 1); }
      eval { Qualified::Moo->new() };
      die "missing required attribute accepted" unless $@ =~ /name/;
    '';
  };

  perl-parallel-forkmanager = mkPerlProbe {
    package = "perl-parallel-forkmanager";
    primaryInput = "Two independent child tasks writing distinct completion files.";
    primaryOperation = "Run both tasks through Parallel::ForkManager and wait for them.";
    primaryExpected = "Both child processes finish and both completion files contain their task number.";
    primaryProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings; use Parallel::ForkManager;
      my $manager = Parallel::ForkManager->new(2);
      for my $number (1, 2) {
          next if $manager->start($number);
          open my $output, ">", "child-$number" or die "cannot create child result";
          print {$output} $number;
          close $output;
          $manager->finish(0);
      }
      $manager->wait_all_children;
      for my $number (1, 2) {
          open my $input, "<", "child-$number" or die "child result missing";
          local $/; die "wrong child result" unless <$input> eq "$number";
      }
    '';
    badInput = "A temporary directory path that does not exist.";
    badOperation = "Construct a fork manager using the invalid state directory.";
    badExpected = "Parallel::ForkManager rejects the missing directory.";
    badProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings; use Parallel::ForkManager;
      eval { Parallel::ForkManager->new(2, "qualification-missing-directory") };
      die "missing temporary directory accepted" unless $@ =~ /doesn't exist/;
    '';
  };

  perl-role-tiny = mkPerlProbe {
    package = "perl-role-tiny";
    primaryInput = "A role requiring name and providing a label method, plus a class implementing name.";
    primaryOperation = "Apply the role to the class and call the provided method.";
    primaryExpected = "Role::Tiny composes the method and it returns qualified.";
    primaryProgram = ''
      use strict; use warnings;
      { package Qualified::Role; use Role::Tiny; requires "name"; sub label { shift->name } }
      { package Qualified::Class; sub name { "qualified" } }
      Role::Tiny->apply_role_to_package("Qualified::Class", "Qualified::Role");
      die "role method unavailable" unless Qualified::Class->label eq "qualified";
    '';
    badInput = "A class that lacks a method required by the role.";
    badOperation = "Apply the role to the incomplete class.";
    badExpected = "Role::Tiny rejects composition and identifies the missing requirement.";
    badProgram = ''
      use strict; use warnings;
      { package Qualified::Role; use Role::Tiny; requires "required_method"; }
      { package Qualified::Incomplete; }
      eval { Role::Tiny->apply_role_to_package("Qualified::Incomplete", "Qualified::Role") };
      die "unsatisfied role accepted" unless $@ =~ /required_method/;
    '';
  };

  perl-sub-quote = mkPerlProbe {
    package = "perl-sub-quote";
    primaryInput = "The Perl expression adding its first two arguments.";
    primaryOperation = "Compile the expression into a named subroutine with Sub::Quote and invoke it.";
    primaryExpected = "The generated subroutine returns 42 for inputs 19 and 23.";
    primaryProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings; use Sub::Quote qw(quote_sub);
      my $sum = quote_sub("Qualified::sum", q{$_[0] + $_[1]});
      die "quoted subroutine failed" unless $sum->(19, 23) == 42;
    '';
    badInput = "A generated subroutine body containing invalid Perl syntax.";
    badOperation = "Compile and invoke the malformed body through Sub::Quote.";
    badExpected = "Sub::Quote rejects the malformed generated source.";
    badProgram = ''
      ${subQuoteWarningGuard}
      use strict; use warnings; use Sub::Quote qw(quote_sub);
      eval { my $sub = quote_sub("Qualified::invalid", q{this is !!!}); $sub->() };
      die "invalid generated source accepted" unless $@;
    '';
  };

  perl-time-duration = mkPerlProbe {
    package = "perl-time-duration";
    primaryInput = "An exact duration of 3661 seconds.";
    primaryOperation = "Render the duration through Time::Duration.";
    primaryExpected = "The module reports one hour, one minute, and one second.";
    primaryProgram = ''
      use strict; use warnings; use Time::Duration qw(duration_exact);
      my $rendered = duration_exact(3661);
      die "wrong duration" unless $rendered eq "1 hour, 1 minute, and 1 second";
    '';
    badInput = "A duration value containing no numeric representation.";
    badOperation = "Render the malformed value while treating numeric warnings as rejection.";
    badExpected = "Time::Duration rejects the nonnumeric duration.";
    badProgram = ''
      use strict; use warnings; use Time::Duration qw(duration_exact);
      local $SIG{__WARN__} = sub { die @_ };
      eval { duration_exact("qualification-invalid") };
      die "nonnumeric duration accepted" unless $@;
    '';
  };
}
