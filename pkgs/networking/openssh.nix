##! OpenSSH — Secure shell client and server
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
  zlib,
}: let
  version = "10.0p1";
in
  mkDerivation {
    pname = "openssh";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${version}.tar.gz"
      ];
      hash = "sha256-AhoucJoO30JQsSVr1anlAEEakN3avqgw7VnO+Q652Fw=";
    };

    buildDeps = [make];
    runtimeDeps = [
      openssl
      zlib
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openssh-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc/ssh \
            --with-ssl-dir=${openssl} \
            --with-zlib=${zlib} \
            --with-privsep-path=$out/var/empty/sshd \
            --with-privsep-user=sshd \
            --without-pam \
            --disable-strip
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
          # Strip setuid bits from install (not available in Nix sandbox)
          sed -i 's/-m 4711/-m 0755/g' Makefile
          make install
        '';
      }
    ];

    meta = {
      description = "OpenSSH — secure shell connectivity tools";
      homepage = "https://www.openssh.com";
      license = "BSD-2-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-openssh-version";
        tool = self;
        command = "ssh -V 2>&1";
      };

      keygen = testing.mkVMTest {
        name = "tool-openssh-keygen";
        rootfsDeps = [self];
        testScript = ''
          echo "==> Generating ed25519 keypair"
          ssh-keygen -t ed25519 -f /tmp/testkey -N ""
          echo "==> Verifying key files exist"
          test -f /tmp/testkey
          test -f /tmp/testkey.pub
          echo "==> ssh-keygen test passed"
        '';
      };
    };
  }
