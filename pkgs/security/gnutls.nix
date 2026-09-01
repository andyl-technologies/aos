{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  nettle,
  gmp,
  libtasn1,
  zlib,
}: let
  version = "3.8.5";
  majorMinor = "3.8";
in
  mkDerivation {
    pname = "gnutls";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.gnupg.org/ftp/gcrypt/gnutls/v${majorMinor}/gnutls-${version}.tar.xz"
        "https://mirrors.dotsrc.org/gcrypt/gnutls/v${majorMinor}/gnutls-${version}.tar.xz"
      ];
      hash = "sha256-ZiaaLP4OHC2r7Ie9u9irZW85bt2aQN0AaXjgA8+lK/w=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [nettle gmp libtasn1 zlib];
    propagatedDeps = [nettle libtasn1];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gnutls-${version}
        '';
      }
      {
        # No p11-kit, no TPM provider (we are bringing up the TPM stack,
        # not consuming it here), bundled libunistring to avoid an extra
        # package. certtool is kept — swtpm's localca uses it.
        name = "configure";
        script = ''
          # Default X.509 trust store: the canonical runtime path owned by the
          # aos.security.pki module (modules/security/pki.nix), NOT a store
          # path — so operators can extend the trust store without rebuilding
          # gnutls. gnutls_certificate_set_x509_system_trust() (chrony NTS,
          # etc.) reads this file at runtime.
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-default-trust-store-file=/etc/ssl/certs/ca-certificates.crt \
            --disable-static \
            --without-p11-kit \
            --with-included-unistring \
            --without-tpm \
            --without-tpm2 \
            --disable-libdane \
            --disable-cxx \
            --disable-guile \
            --disable-doc \
            --disable-tests \
            --disable-full-test-suite \
            --disable-nls
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "GnuTLS — TLS/SSL and certificate library";
      homepage = "https://www.gnutls.org/";
      license = "LGPL-2.1-or-later";
    };
  }
