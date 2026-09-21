##! Exercises core Perl module APIs through each package's retained runtime closure.
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
  perl-algorithm-diff = mkPerlProbe {
    package = "perl-algorithm-diff";
    primaryInput = "The sequences alpha, beta, gamma and alpha, delta, gamma.";
    primaryOperation = "Compute their longest common subsequence through Algorithm::Diff.";
    primaryExpected = "The module returns alpha and gamma in order.";
    primaryProgram = ''
      use strict; use warnings; use Algorithm::Diff qw(LCS);
      my @common = LCS([qw(alpha beta gamma)], [qw(alpha delta gamma)]);
      die "wrong common sequence" unless join(",", @common) eq "alpha,gamma";
    '';
    badInput = "A scalar supplied where Algorithm::Diff requires a sequence reference.";
    badOperation = "Attempt to compute a diff with the malformed operand.";
    badExpected = "Algorithm::Diff rejects the non-array sequence.";
    badProgram = ''
      use strict; use warnings; use Algorithm::Diff ();
      eval { Algorithm::Diff::diff("not-an-array", []) };
      die "invalid sequence accepted" unless $@;
    '';
  };

  perl-b-cow = mkPerlProbe {
    package = "perl-b-cow";
    primaryInput = "A Perl string eligible for copy-on-write storage.";
    primaryOperation = "Inspect copy-on-write capability and its maximum reference count.";
    primaryExpected = "B::COW reports support and a positive reference-count limit.";
    primaryProgram = ''
      use strict; use warnings; use B::COW qw(can_cow cowrefcnt_max);
      die "copy-on-write unavailable" unless can_cow();
      die "invalid reference limit" unless cowrefcnt_max() > 0;
    '';
    badInput = "An export name outside B::COW's documented API.";
    badOperation = "Import the unsupported symbol from B::COW.";
    badExpected = "The module's Exporter contract rejects the unknown symbol.";
    badProgram = ''
      use strict; use warnings;
      eval q{ use B::COW qw(qualification_invalid); 1 };
      die "invalid export accepted" unless $@ =~ /not exported/;
    '';
  };

  perl-clone = mkPerlProbe {
    package = "perl-clone";
    primaryInput = "A nested hash containing an array reference.";
    primaryOperation = "Deep-clone the structure and mutate only the clone.";
    primaryExpected = "The clone is independent and the source array remains unchanged.";
    primaryProgram = ''
      use strict; use warnings; use Clone qw(clone);
      my $source = { values => [1, 2] };
      my $copy = clone($source);
      push @{$copy->{values}}, 3;
      die "clone shares nested storage" unless @{$source->{values}} == 2 && @{$copy->{values}} == 3;
    '';
    badInput = "A clone request with its required scalar argument omitted.";
    badOperation = "Invoke Clone::clone without an input value.";
    badExpected = "Clone rejects the call for having too few arguments.";
    badProgram = ''
      use strict; use warnings; use Clone qw(clone);
      eval q{ clone() };
      die "missing input accepted" unless $@ =~ /Not enough arguments/;
    '';
  };

  perl-encode-locale = mkPerlProbe {
    package = "perl-encode-locale";
    primaryInput = "One UTF-8 command-line argument decoded in void context.";
    primaryOperation = "Configure UTF-8 as the locale encoding and decode @ARGV in place.";
    primaryExpected = "Encode::Locale preserves the decoded qualification argument.";
    primaryProgram = ''
      use strict; use warnings; use Encode::Locale qw(decode_argv);
      Encode::Locale::reinit("UTF-8", "UTF-8");
      local @ARGV = ("qualification");
      decode_argv();
      die "argument changed" unless $ARGV[0] eq "qualification";
    '';
    badInput = "A scalar-context request for the void-only decode_argv operation.";
    badOperation = "Call decode_argv where a return value is requested.";
    badExpected = "Encode::Locale rejects the unsupported calling context.";
    badProgram = ''
      use strict; use warnings; use Encode::Locale qw(decode_argv);
      eval { my $value = decode_argv(); };
      die "scalar context accepted" unless $@;
    '';
  };

  perl-io-html = mkPerlProbe {
    package = "perl-io-html";
    primaryInput = "An HTML meta charset declaration for UTF-8.";
    primaryOperation = "Detect the declared encoding with IO::HTML.";
    primaryExpected = "The module normalizes the declaration to utf-8-strict.";
    primaryProgram = ''
      use strict; use warnings; use IO::HTML qw(find_charset_in);
      my $encoding = find_charset_in(q{<meta charset="UTF-8"><p>qualified</p>});
      die "charset not detected" unless defined($encoding) && $encoding =~ /utf-8/i;
    '';
    badInput = "An HTML meta declaration naming a nonexistent character encoding.";
    badOperation = "Attempt to resolve the unsupported encoding.";
    badExpected = "IO::HTML declines the unknown charset.";
    badProgram = ''
      use strict; use warnings; use IO::HTML qw(find_charset_in);
      my $encoding = find_charset_in(q{<meta charset="qualification-invalid">});
      die "invalid charset accepted" if defined $encoding;
    '';
  };

  perl-lwp-mediatypes = mkPerlProbe {
    package = "perl-lwp-mediatypes";
    primaryInput = "The archive name qualification.tar.gz.";
    primaryOperation = "Infer its media type and content encoding.";
    primaryExpected = "LWP::MediaTypes identifies application/x-tar with gzip encoding.";
    primaryProgram = ''
      use strict; use warnings; use LWP::MediaTypes qw(guess_media_type);
      my ($type, $encoding) = guess_media_type("qualification.tar.gz");
      die "wrong media inference" unless $type eq "application/x-tar" && $encoding eq "gzip";
    '';
    badInput = "An unregistered application/qualification-invalid media type.";
    badOperation = "Request a preferred filename suffix for the unknown media type.";
    badExpected = "LWP::MediaTypes returns no suffix.";
    badProgram = ''
      use strict; use warnings; use LWP::MediaTypes qw(media_suffix);
      my $suffix = media_suffix("application/qualification-invalid");
      die "unknown media type accepted" if defined $suffix;
    '';
  };

  perl-module-runtime = mkPerlProbe {
    package = "perl-module-runtime";
    primaryInput = "The valid module name Qualification::Example.";
    primaryOperation = "Convert the name to its notional module filename.";
    primaryExpected = "Module::Runtime returns Qualification/Example.pm.";
    primaryProgram = ''
      use strict; use warnings; use Module::Runtime qw(module_notional_filename);
      die "wrong filename" unless module_notional_filename("Qualification::Example") eq "Qualification/Example.pm";
    '';
    badInput = "A module name containing a path traversal segment.";
    badOperation = "Validate and convert the malformed module name.";
    badExpected = "Module::Runtime rejects the invalid module name.";
    badProgram = ''
      use strict; use warnings; use Module::Runtime qw(check_module_name);
      eval { check_module_name("Qualification::../Invalid") };
      die "invalid module name accepted" unless $@ =~ /not a module name/;
    '';
  };

  perl-readonly = mkPerlProbe {
    package = "perl-readonly";
    primaryInput = "A scalar initialized to the value qualified.";
    primaryOperation = "Declare it read-only and read the stored value.";
    primaryExpected = "Readonly preserves the exact scalar value.";
    primaryProgram = ''
      use strict; use warnings; use Readonly;
      Readonly my $value => "qualified";
      die "wrong readonly value" unless $value eq "qualified";
    '';
    badInput = "An assignment that attempts to replace a read-only scalar.";
    badOperation = "Mutate the protected value.";
    badExpected = "Readonly rejects the assignment and preserves the original value.";
    badProgram = ''
      use strict; use warnings; use Readonly;
      Readonly my $value => "qualified";
      eval { $value = "changed"; };
      die "readonly assignment accepted" unless $@ && $value eq "qualified";
    '';
  };

  perl-regexp-common = mkPerlProbe {
    package = "perl-regexp-common";
    primaryInput = "The dotted-quad IPv4 address 192.0.2.25.";
    primaryOperation = "Match it with Regexp::Common's IPv4 pattern.";
    primaryExpected = "The address matches and is captured intact.";
    primaryProgram = ''
      use strict; use warnings; use Regexp::Common qw(net);
      my $input = "192.0.2.25";
      die "IPv4 address did not match" unless $input =~ /\A($RE{net}{IPv4})\z/ && $1 eq $input;
    '';
    badInput = "The out-of-range dotted quad 999.0.2.25.";
    badOperation = "Match it with the IPv4 pattern.";
    badExpected = "Regexp::Common rejects the invalid address.";
    badProgram = ''
      use strict; use warnings; use Regexp::Common qw(net);
      my $input = "999.0.2.25";
      die "invalid IPv4 address accepted" if $input =~ /\A$RE{net}{IPv4}\z/;
    '';
  };
}
