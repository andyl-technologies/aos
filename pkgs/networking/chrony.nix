##! Chrony — NTP client and server
{
  mkDerivation,
  fetchurl,
  buildPackages,
  libcap,
  nettle,
  gnutls,
  stdenv,
}: let
  version = "4.8";
  isDarwin = stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "chrony";
    inherit version;

    src = fetchurl {
      urls = [
        "https://chrony-project.org/releases/chrony-${version}.tar.gz"
      ];
      hash = "sha256-M+qOsqTa6qUG6Pyv1dbYkCftby8GCWRcbxSbVg0wFwY=";
    };

    buildDeps = [
      buildPackages.gnumake
      buildPackages.pkg-config
    ];
    runtimeDeps =
      (
        if isDarwin
        then []
        else [libcap]
      )
      ++ [
        # nettle: SECHASH backend (SHA-1/2/3 + AES-CMAC) for symmetric-key NTP
        # auth, and AES-SIV for NTS cookie encryption.
        nettle
        # gnutls: TLS 1.3 for NTS-KE (RFC 8915). chrony verifies NTS servers
        # against gnutls's system trust store, which AOS wires to the Mozilla CA
        # bundle in pkgs/security/gnutls.nix.
        gnutls
      ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd chrony-${version}
        '';
      }
      {
        name = "configure";
        script =
          if isDarwin
          then ''
            ./configure \
              --prefix=$out \
              --sysconfdir=/etc \
              --localstatedir=$out/var \
              --with-pidfile=/run/chrony/chronyd.pid \
              --host-system=Darwin \
              --host-release=20.0.0 \
              --host-machine=${stdenv.hostPlatform.darwinArch} \
              --without-editline \
              --without-readline

            # NTS (RFC 8915) is on by default in chrony's configure, but it
            # silently disables itself if no TLS library is detected. Fail the
            # build loudly if gnutls was not picked up, so a broken NTS build is
            # never shipped as a "successful" one.
            grep -q '#define FEAT_NTS' config.h || {
              echo "ERROR: chrony configured without NTS (gnutls not detected)" >&2
              exit 1
            }
          ''
          else ''
            ./configure \
              --prefix=$out \
              --sysconfdir=/etc \
              --localstatedir=$out/var \
              --with-pidfile=/run/chrony/chronyd.pid \
              --without-editline \
              --without-readline

            # NTS (RFC 8915) is on by default in chrony's configure, but it
            # silently disables itself if no TLS library is detected. Fail the
            # build loudly if gnutls was not picked up, so a broken NTS build is
            # never shipped as a "successful" one.
            grep -q '#define FEAT_NTS' config.h || {
              echo "ERROR: chrony configured without NTS (gnutls not detected)" >&2
              exit 1
            }
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
          make install DESTDIR=""
        '';
      }
    ];

    meta = {
      description = "Chrony — versatile NTP implementation";
      homepage = "https://chrony-project.org";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      version = testing.mkToolCheck {
        pname = "tool-chrony";
        tool = self;
        command = "chronyd --version";
      };

      config-validity = testing.mkVMTest {
        name = "cross-cutting-chrony-config-validity";
        rootfsDeps = [self];
        testScript = ''
          echo "==> Testing chronyd config parsing"
          cat > /tmp/chrony.conf << 'CHRONYCFG'
          pool pool.ntp.org iburst
          driftfile /var/lib/chrony/drift
          makestep 1.0 3
          rtcsync
          CHRONYCFG
          chronyd -p -f /tmp/chrony.conf
          echo "    chronyd config: valid"
          echo "Chrony config validity: PASS"
        '';
      };
    };
  }
