##! wget — Non-interactive network downloader
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  pkg-config,
  perl,
  lzip,
  c-ares,
  gpgme,
  glib,
  glibc-locales,
  libidn2,
  libmetalink,
  libproxy,
  libpsl,
  libunistring,
  zlib,
  pcre2,
  util-linux,
  openssl,
  perl-clone,
  perl-encode-locale,
  perl-http-daemon,
  perl-http-date,
  perl-http-message,
  perl-io-html,
  perl-io-socket-ssl,
  perl-lwp-mediatypes,
  perl-mozilla-ca,
  perl-net-ssleay,
  perl-timedate,
  perl-uri,
}: let
  version = "1.25.0";
  perlTestDeps = [
    perl-clone
    perl-encode-locale
    perl-http-daemon
    perl-http-date
    perl-http-message
    perl-io-html
    perl-io-socket-ssl
    perl-lwp-mediatypes
    perl-mozilla-ca
    perl-net-ssleay
    perl-timedate
    perl-uri
  ];
  perlTestPath = builtins.concatStringsSep ":" (
    map (dependency: "${dependency}/lib/perl5") perlTestDeps
  );
  cve58471 = fetchurl {
    urls = ["https://gitlab.com/gnuwget/wget/-/commit/c2640fe5171c59f87c58dc9fcb195b2d18b010ee.patch"];
    hash = "sha256-HPcF2AIENb4G/o2soas9+ozSvJOTe2E9+xxJ1WE1h44=";
  };
  cve58470 = fetchurl {
    urls = ["https://gitlab.com/gnuwget/wget/-/commit/43d3ba9336bc94937e6fae2365c6ffd30c34ffcf.patch"];
    hash = "sha256-9K3jRFqcFCYnHzrlykvIk7B+wnu6mvhW2/zaiWAvR4g=";
  };
  cve58469 = fetchurl {
    urls = ["https://gitlab.com/gnuwget/wget/-/commit/37a40fcb450153f69537c7cbc2a7a4fb0b6f7826.patch"];
    hash = "sha256-2te6WvHqKEx7Q9EYgWMIaBDD1/CJRIVNdHAVMEmLWEY=";
  };
  cve58472 = fetchurl {
    urls = ["https://gitlab.com/gnuwget/wget/-/commit/dd692d9cea5335b181d877ae917fe6e75587a812.patch"];
    hash = "sha256-AWLWDP6a1G5Hvx3KWaJbiPJtNFRgMMA4CuITy5gr8ww=";
  };
in
  mkDerivation {
    pname = "wget";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftpmirror.gnu.org/gnu/wget/wget-${version}.tar.lz"
        "https://ftp.gnu.org/gnu/wget/wget-${version}.tar.lz"
      ];
      hash = "sha256-GSJcx1awoIj8gRSNxqQKDI8ymvf9hIPxx7L+UPTgih8=";
    };

    buildDeps = [gnumake gettext pkg-config perl lzip glib.dev glibc-locales] ++ perlTestDeps;
    runtimeDeps = [
      c-ares
      gpgme
      glib
      libidn2
      libmetalink
      libproxy
      libpsl
      libunistring
      zlib
      pcre2
      util-linux
      openssl
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          lzip -dc "$src" | tar xf -
          cd wget-${version}

          patch -p1 < ${cve58471}
          patch -p1 < ${cve58470}
          patch -p1 < ${cve58469}
          patch -p1 < ${cve58472}

          # The Metalink sanitizer added by the security backport uses the
          # standard character classification API explicitly.
          sed -i '/#include <fcntl.h>/a #include <ctype.h>' src/metalink.c

          # The Nix build filesystem rejects the deliberately malformed
          # non-UTF-8 filenames used by these six filesystem behavior tests.
          # Keep every protocol and Unicode correctness test that uses valid
          # filenames, including the other IRI, IDN, HTTP, and FTP cases.
          for test in \
            tests/Test-ftp-iri.px \
            tests/Test-ftp-iri-fallback.px \
            tests/Test-ftp-iri-recursive.px \
            tests/Test-ftp-iri-disabled.px \
            tests/Test-iri-disabled.px \
            tests/Test-iri-list.px; do
            sed -i 's/^exit /exit 77; # /' "$test"
          done

          grep -rlZ \
            -e '^#! */usr/bin/perl' \
            -e '^#! */usr/bin/env perl' \
            . | while IFS= read -r -d "" file; do
            sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$file"
          done
          grep -rlZ \
            -e '^#! */bin/sh' \
            -e '^#! */bin/bash' \
            -e '^#! */usr/bin/env sh' \
            -e '^#! */usr/bin/env bash' \
            . | while IFS= read -r -d "" file; do
            sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$file"
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-libproxy \
            --with-ssl=openssl \
            --with-libpsl \
            --with-metalink \
            --with-cares \
            --with-gpgme-prefix=${gpgme}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          LOCPATH=${glibc-locales}/lib/locale \
            LC_ALL=C.UTF-8 \
            PERL5LIB=${perlTestPath} \
            make -j"$NIX_BUILD_CORES" check \
              TESTS_ENVIRONMENT='export LOCPATH=${glibc-locales}/lib/locale; export LC_ALL=C.UTF-8;'
        '';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-wget";
        tool = self;
        command = "wget --version | grep -E 'ssl/openssl|https'";
      };
    };

    meta = {
      description = "Non-interactive network downloader";
      homepage = "https://www.gnu.org/software/wget/";
      license = "GPL-3.0-or-later";
      mainProgram = "wget";
    };
  }
