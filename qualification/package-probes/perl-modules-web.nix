##! Exercises Perl web, URI, date, and TLS module APIs offline.
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
  perl-http-daemon = mkPerlProbe {
    package = "perl-http-daemon";
    primaryInput = "A loopback HTTP listener requesting an ephemeral port.";
    primaryOperation = "Create the listener with HTTP::Daemon and inspect its advertised URL.";
    primaryExpected = "The daemon binds loopback and reports a nonzero local port in an HTTP URL.";
    primaryProgram = ''
      use strict; use warnings; use HTTP::Daemon;
      my $daemon = HTTP::Daemon->new(LocalAddr => "127.0.0.1", LocalPort => 0, ReuseAddr => 1);
      die "listener creation failed" unless $daemon && $daemon->sockport > 0;
      die "wrong listener URL" unless $daemon->url =~ m{\Ahttp://127\.0\.0\.1:\d+/\z};
      $daemon->close;
    '';
    badInput = "A loopback endpoint already occupied by another HTTP listener.";
    badOperation = "Attempt to bind a second daemon to the occupied endpoint.";
    badExpected = "HTTP::Daemon declines the conflicting bind request.";
    badProgram = ''
      use strict; use warnings; use HTTP::Daemon;
      my $first = HTTP::Daemon->new(LocalAddr => "127.0.0.1", LocalPort => 0);
      die "first listener creation failed" unless $first;
      my $second = HTTP::Daemon->new(LocalAddr => "127.0.0.1", LocalPort => $first->sockport);
      die "occupied endpoint accepted" if defined $second;
      $first->close;
    '';
  };

  perl-http-date = mkPerlProbe {
    package = "perl-http-date";
    primaryInput = "The IMF-fixdate Sun, 06 Nov 1994 08:49:37 GMT.";
    primaryOperation = "Parse the HTTP date into Unix epoch seconds.";
    primaryExpected = "HTTP::Date returns 784111777.";
    primaryProgram = ''
      use strict; use warnings; use HTTP::Date qw(str2time time2str);
      my $epoch = str2time("Sun, 06 Nov 1994 08:49:37 GMT");
      die "wrong epoch" unless $epoch == 784111777;
      die "round trip failed" unless time2str($epoch) eq "Sun, 06 Nov 1994 08:49:37 GMT";
    '';
    badInput = "A date string without a valid HTTP date grammar.";
    badOperation = "Parse the malformed date with HTTP::Date.";
    badExpected = "HTTP::Date returns no timestamp.";
    badProgram = ''
      use strict; use warnings; use HTTP::Date qw(str2time);
      die "invalid date accepted" if defined str2time("qualification-invalid-date");
    '';
  };

  perl-http-message = mkPerlProbe {
    package = "perl-http-message";
    primaryInput = "A POST request with one content-type header and a fixed body.";
    primaryOperation = "Construct and serialize the request through HTTP::Request.";
    primaryExpected = "The serialized message contains the request line, header, and exact body.";
    primaryProgram = ''
      use strict; use warnings; use HTTP::Request;
      my $request = HTTP::Request->new("POST", "http://example.test/qualified");
      $request->header("Content-Type" => "text/plain");
      $request->content("payload");
      my $wire = $request->as_string("\r\n");
      die "request line missing" unless $wire =~ /\APOST http:\/\/example\.test\/qualified\r\n/;
      die "body missing" unless $wire =~ /\r\n\r\npayload\z/;
    '';
    badInput = "A scalar supplied to the reference-only content_ref setter.";
    badOperation = "Replace message content through content_ref with the invalid value.";
    badExpected = "HTTP::Message rejects the non-reference content value.";
    badProgram = ''
      use strict; use warnings; use HTTP::Message;
      my $message = HTTP::Message->new;
      eval { $message->content_ref("not-a-reference") };
      die "invalid content reference accepted" unless $@ =~ /non-ref/;
    '';
  };

  perl-io-socket-ssl = mkPerlProbe {
    package = "perl-io-socket-ssl";
    primaryInput = "The package's configured default certificate authority source.";
    primaryOperation = "Resolve the default CA configuration without opening a socket.";
    primaryExpected = "IO::Socket::SSL returns an existing CA file or directory.";
    primaryProgram = ''
      use strict; use warnings; use IO::Socket::SSL;
      my %ca = IO::Socket::SSL::default_ca();
      my $path = $ca{SSL_ca_file} // $ca{SSL_ca_path};
      die "default CA unavailable" unless defined($path) && -e $path;
    '';
    badInput = "Text that is not a PEM X.509 certificate.";
    badOperation = "Parse it with IO::Socket::SSL's certificate utility.";
    badExpected = "The utility rejects the malformed certificate.";
    badProgram = ''
      use strict; use warnings; use IO::Socket::SSL::Utils qw(PEM_string2cert);
      eval { PEM_string2cert("not a certificate") };
      die "malformed certificate accepted" unless $@ =~ /cannot parse/;
    '';
  };

  perl-mozilla-ca = mkPerlProbe {
    package = "perl-mozilla-ca";
    primaryInput = "A request for the packaged Mozilla certificate bundle.";
    primaryOperation = "Resolve the bundle through Mozilla::CA and inspect its PEM boundary.";
    primaryExpected = "The API returns an existing file beginning with a certificate PEM block.";
    primaryProgram = ''
      use strict; use warnings; use Mozilla::CA;
      my $path = Mozilla::CA::SSL_ca_file();
      open my $input, "<", $path or die "cannot open CA bundle";
      local $/; my $bundle = <$input>;
      die "invalid CA bundle" unless $bundle =~ /-----BEGIN CERTIFICATE-----/;
    '';
    badInput = "A request for an unsupported named certificate bundle API.";
    badOperation = "Dispatch the nonexistent bundle selector on Mozilla::CA.";
    badExpected = "Perl rejects the method because Mozilla::CA exposes only SSL_ca_file.";
    badProgram = ''
      use strict; use warnings; use Mozilla::CA;
      eval { Mozilla::CA->qualification_invalid_bundle() };
      die "unsupported bundle selector accepted" unless $@ =~ /Can't locate object method/;
    '';
  };

  perl-net-ssleay = mkPerlProbe {
    package = "perl-net-ssleay";
    primaryInput = "A request for the linked TLS library version.";
    primaryOperation = "Query OpenSSL through Net::SSLeay's public version API.";
    primaryExpected = "The binding returns a nonempty OpenSSL version string.";
    primaryProgram = ''
      use strict; use warnings; use Net::SSLeay;
      my $version = Net::SSLeay::SSLeay_version(0);
      die "TLS version unavailable" unless defined($version) && $version =~ /OpenSSL/;
    '';
    badInput = "Text without a PEM certificate boundary.";
    badOperation = "Decode the malformed text through Net::SSLeay's X.509 BIO API.";
    badExpected = "The decoder returns no certificate object and records an OpenSSL error.";
    badProgram = ''
      use strict; use warnings; use Net::SSLeay;
      my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
      Net::SSLeay::BIO_write($bio, "not a certificate");
      my $certificate = Net::SSLeay::PEM_read_bio_X509($bio);
      Net::SSLeay::BIO_free($bio);
      die "malformed certificate accepted" if $certificate;
      die "rejection lacked TLS error" unless Net::SSLeay::ERR_get_error();
    '';
  };

  perl-timedate = mkPerlProbe {
    package = "perl-timedate";
    primaryInput = "The UTC timestamp 1994-11-06 08:49:37 GMT.";
    primaryOperation = "Parse the timestamp through Date::Parse.";
    primaryExpected = "Date::Parse returns Unix epoch 784111777.";
    primaryProgram = ''
      use strict; use warnings; use Date::Parse qw(str2time);
      die "wrong parsed timestamp" unless str2time("1994-11-06 08:49:37 GMT") == 784111777;
    '';
    badInput = "A string with no recognizable date fields.";
    badOperation = "Parse the malformed timestamp through Date::Parse.";
    badExpected = "Date::Parse returns no timestamp.";
    badProgram = ''
      use strict; use warnings; use Date::Parse qw(str2time);
      die "invalid timestamp accepted" if defined str2time("qualification-invalid-date");
    '';
  };

  perl-uri = mkPerlProbe {
    package = "perl-uri";
    primaryInput = "The relative URI ../qualified?q=1 and HTTPS base https://Example.TEST/a/b/.";
    primaryOperation = "Resolve and canonicalize the relative URI through the URI API.";
    primaryExpected = "The URI resolves to /a/qualified, lowercases the host, and retains the query.";
    primaryProgram = ''
      use strict; use warnings; use URI;
      my $uri = URI->new_abs("../qualified?q=1", "HTTPS://Example.TEST/a/b/")->canonical;
      die "wrong canonical URI" unless $uri->as_string eq "https://example.test/a/qualified?q=1";
    '';
    badInput = "A relative URI without the required base URI.";
    badOperation = "Resolve the relative URI through URI->new_abs.";
    badExpected = "URI rejects the missing base argument.";
    badProgram = ''
      use strict; use warnings; use URI;
      eval { URI->new_abs("child", undef) };
      die "missing base accepted" unless $@ =~ /Missing base argument/;
    '';
  };
}
