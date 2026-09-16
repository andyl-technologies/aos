##! perl-net-ssleay — OpenSSL bindings for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  openssl,
  zlib,
}: let
  version = "1.96";
  runtimeClosureManifest = builtins.concatStringsSep "\n" (map builtins.toString [perl openssl zlib]);
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-net-ssleay";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The binding returns a nonempty OpenSSL version string.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Net::SSLeay;\nmy $version = Net::SSLeay::SSLeay_version(0);\ndie \"TLS version unavailable\" unless defined($version) && $version =~ /OpenSSL/;\n";
        };
        "input" = "A request for the linked TLS library version.";
        "operation" = "Query OpenSSL through Net::SSLeay's public version API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-net-ssleay operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-net-ssleay operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The decoder returns no certificate object and records an OpenSSL error.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Net::SSLeay;\nmy $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());\nNet::SSLeay::BIO_write($bio, \"not a certificate\");\nmy $certificate = Net::SSLeay::PEM_read_bio_X509($bio);\nNet::SSLeay::BIO_free($bio);\ndie \"malformed certificate accepted\" if $certificate;\ndie \"rejection lacked TLS error\" unless Net::SSLeay::ERR_get_error();\n";
        };
        "input" = "Text without a PEM certificate boundary.";
        "operation" = "Decode the malformed text through Net::SSLeay's X.509 BIO API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-net-ssleay operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-net-ssleay operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/C/CH/CHRISN/Net-SSLeay-${version}.tar.gz"];
      hash = "sha256-qyE2kWhfsqV2xmnLyNkmb4FloxVjrRW3xAMLlK38B1M=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [perl openssl zlib];
    propagatedDeps = [openssl zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd Net-SSLeay-${version}
        '';
      }
      {
        name = "patch";
        # Backport upstream's OpenSSL 4 support through merge a55abab.
        script = ''patch -p1 < ${./net-ssleay-openssl-4.patch}'';
      }
      {
        name = "configure";
        script = ''
          export OPENSSL_PREFIX=${openssl}
          ${perl}/bin/perl Makefile.PL \
            INSTALL_BASE="$out" \
            CC="$CC" \
            LD="$CC"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
          rm -f "$out"/lib/perl5/*/*/perllocal.pod "$out"/lib/perl5/*/*/.packlist

          # Retain the interpreter and libraries required to load the XS module.
          mkdir -p "$out/nix-support"
          cat > "$out/nix-support/runtime-closure" <<'EOF'
          ${runtimeClosureManifest}
          EOF

          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MNet::SSLeay -e 1
        '';
      }
    ];

    meta = {
      description = "OpenSSL bindings for Perl";
      homepage = "https://metacpan.org/dist/Net-SSLeay";
      license = "Artistic-2.0";
    };
  }
