##! GnuPG — complete OpenPGP / X.509 implementation (the `gpg` tool)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libgpg-error,
  libgcrypt,
  libassuan,
  libksba,
  npth,
  libusb1,
  zlib,
  bzip2,
  readline,
  sqlite,
}: let
  version = "2.5.20";
in
  mkDerivation {
    pname = "gnupg";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/gnupg/gnupg-${version}.tar.bz2"
      ];
      hash = "sha256-ZGEmbpnDCEGaN5q+bDVtVMIUE2xFib1llRCRE4mJ/8Y=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    # The GnuPG crypto stack plus compression (zlib/bzip2), readline for the
    # interactive prompts, sqlite for the keyboxd key database, and libusb1 so
    # scdaemon's built-in CCID driver can drive USB smartcard readers without a
    # running pcscd.
    runtimeDeps = [
      libgpg-error
      libgcrypt
      libassuan
      libksba
      npth
      libusb1
      zlib
      bzip2
      readline
      sqlite
    ];
    propagatedDeps = [];

    # GnuPG's secure-memory pool and several internal structures use trailing
    # flexible arrays that are over-allocated and written past their declared
    # extent. -fstrict-flex-arrays=3 sizes those arrays exactly, so
    # _FORTIFY_SOURCE aborts the *running* gpg/gpg-agent with "*** buffer
    # overflow detected ***" during ordinary operations (key generation,
    # signing) — the build itself links fine, so this only shows up at runtime.
    # Step down to level 1 (where the trailing arrays stay flexible); fortify3
    # and the rest of the hardening remain on. Mirrors libgpg-error/libksba/acl.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gnupg-${version}
        '';
      }
      {
        # scdaemon's internal CCID driver does `#include <libusb.h>`, but libusb1
        # installs that header under .../include/libusb-1.0/. Adding the subdir to
        # CPPFLAGS lets both configure's libusb probe and the build itself find
        # it, so the CCID driver (smartcard support) is compiled in. This is the
        # robust, version-independent equivalent of nixpkgs'
        # fix-libusb-include-path.patch.
        #
        # The crypto libraries are located via their *-config scripts
        # (--with-*-prefix); sqlite is found through pkg-config. keyserver TLS
        # (gnutls) and LDAP (openldap) are left out, so dirmngr auto-disables
        # those backends.
        #
        # The 2.5 development series does not ship pre-built man pages, so the
        # install phase needs the yat2m generator. It lives in libgpg-error's bin
        # (which isn't on PATH here), so point configure's AC_PATH_PROG at it
        # explicitly — same approach as GPGRT_CONFIG.
        name = "configure";
        script = ''
          export CPPFLAGS="-I${libusb1}/include/libusb-1.0 $CPPFLAGS"
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --enable-large-secmem \
            --disable-nls \
            --with-libgpg-error-prefix=${libgpg-error} \
            --with-libgcrypt-prefix=${libgcrypt} \
            --with-libassuan-prefix=${libassuan} \
            --with-ksba-prefix=${libksba} \
            --with-npth-prefix=${npth} \
            GPGRT_CONFIG=${libgpg-error}/bin/gpgrt-config \
            YAT2M=${libgpg-error}/bin/yat2m
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      smoke = testing.mkVMTest {
        name = "tool-gnupg-smoke";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          set -e
          export GNUPGHOME=/tmp/gnupg
          mkdir -p "$GNUPGHOME"
          chmod 700 "$GNUPGHOME"

          # Generate a key non-interactively, then sign and verify a message.
          # Each gpg invocation runs on its own line (no pipes) so a fatal abort
          # — e.g. a _FORTIFY_SOURCE "buffer overflow detected" — surfaces as a
          # non-zero exit and fails the test under `set -e`, rather than being
          # swallowed by a downstream `| tail`.
          gpg --batch --pinentry-mode loopback --passphrase "" \
            --quick-generate-key "AOS Test <test@andyl.com>" ed25519 sign

          echo "andyl os" > /tmp/msg.txt
          gpg --batch --pinentry-mode loopback --passphrase "" \
            --output /tmp/msg.sig --detach-sign /tmp/msg.txt

          gpg --verify /tmp/msg.sig /tmp/msg.txt

          # scdaemon must report the built-in CCID driver (smartcard support).
          gpg-agent --version
          ${self}/libexec/scdaemon --version

          echo "==> gnupg smoke: passed"
        '';
      };
    };

    meta = {
      description = "Complete OpenPGP and X.509 implementation (the gpg tool)";
      homepage = "https://gnupg.org/";
      license = "GPL-3.0-or-later";
    };
  }
