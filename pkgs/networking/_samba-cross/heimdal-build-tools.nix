##! Build-platform Heimdal code generators for cross-compiling Samba.
##!
##! Samba's embedded Heimdal compiles `asn1_compile` and `compile_et` with the
##! target compiler and then runs them to generate sources. A cross build would
##! therefore execute target binaries. This derivation builds the same two
##! generators from the same Samba source for the build platform, and the
##! cross build selects them through Waf's system-generator switches.
{
  mkDerivation,
  gnumake,
  pkg-config,
  python3,
  perl,
  perl-parse-yapp,
  flex,
  bison,
  gettext,
  acl,
  attr,
  gnutls,
  libcap,
  libtasn1,
  libtirpc,
  liburing,
  libxcrypt,
  lmdb,
  ncurses,
  popt,
  readline,
  rpcsvc-proto,
  zlib,
  src,
  version,
}:
mkDerivation {
  pname = "samba-heimdal-build-tools";
  inherit version src;

  buildDeps = [
    gnumake
    pkg-config
    gettext
    python3
    perl
    perl-parse-yapp
    flex
    bison
    libtasn1
  ];

  # Samba's top-level configure validates its mandatory libraries even when
  # only the generators are built. Neither generator links any of them.
  runtimeDeps = [
    acl
    attr
    gnutls
    libcap
    libtasn1
    libtirpc
    liburing
    libxcrypt
    lmdb
    ncurses
    popt
    readline
    rpcsvc-proto
    zlib
  ];
  propagatedDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd samba-${version}

        # Waf and its helpers execute directly through FHS shebangs.
        find . -type f \( -name '*.py' -o -name 'waf' \) | while read file; do
          if head -n 1 "$file" | grep -Eq '^#! */usr/bin/(env +)?python'; then
            sed -i "1s|^#!.*|#!${python3}/bin/python3|" "$file"
          fi
        done
      '';
    }
    {
      name = "configure";
      script = ''
        export PERL5LIB="${perl-parse-yapp}/lib/perl5''${PERL5LIB:+:$PERL5LIB}"

        # Match the narrow file-server configuration so configure needs no
        # optional service libraries. The generators do not depend on it.
        "$CONFIG_SHELL" ./configure \
          --prefix="$out" \
          --without-ad-dc \
          --disable-python \
          --without-winbind \
          --without-ads \
          --without-ldap \
          --without-json \
          --disable-cups \
          --disable-iprint \
          --disable-avahi \
          --disable-glusterfs \
          --disable-wsp \
          --disable-spotlight \
          --without-libarchive \
          --without-pam \
          --without-regedit \
          --without-cluster-support \
          --with-shared-modules='!DEFAULT'
      '';
    }
    {
      name = "build";
      script = ''
        export PERL5LIB="${perl-parse-yapp}/lib/perl5''${PERL5LIB:+:$PERL5LIB}"
        PYTHONHASHSEED=1 python3 ./buildtools/bin/waf build \
          -j"$NIX_BUILD_CORES" \
          --targets=asn1_compile,compile_et
      '';
    }
    {
      name = "install";
      script = ''
        generatorDirectory=bin/default/third_party/heimdal_build
        install -D -m 0755 "$generatorDirectory/asn1_compile" "$out/bin/asn1_compile"
        install -D -m 0755 "$generatorDirectory/compile_et" "$out/bin/compile_et"

        "$out/bin/asn1_compile" --version
        "$out/bin/compile_et" --version
      '';
    }
  ];

  meta = {
    description = "Samba's embedded Heimdal ASN.1 and error-table compilers for build-time code generation";
    homepage = "https://www.samba.org/";
    license = "BSD-3-Clause";
    mainProgram = "asn1_compile";
  };
}
