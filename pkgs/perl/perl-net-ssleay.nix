##! perl-net-ssleay — OpenSSL bindings for Perl
{
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
    pname = "perl-net-ssleay";
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
