##! OpenSSH — Secure shell client and server
{
  mkDerivation,
  fetchurl,
  gnumake,
  linux-pam,
  openpam,
  openssl,
  zlib,
  bash,
  stdenv,
}: let
  version = "10.3p1";
in
  mkDerivation {
    pname = "openssh";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${version}.tar.gz"
      ];
      hash = "sha256-VmgqNruS3PS08Bb9jsjnQFm3mo3iXBXWcNcx59GORfQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [
        (
          if stdenv.hostPlatform.isDarwin
          then openpam
          else linux-pam
        )
        openssl
        zlib
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
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
        # --sysconfdir=/etc/ssh so the compiled-in default for every ssh
        # tool (ssh-keygen -A, sshd default config lookup, etc.) points
        # at the real runtime config dir. Using $out/etc/ssh bakes a
        # store path into those defaults, which makes `ssh-keygen -A`
        # refuse to regenerate keys because it sees the store's
        # pre-staged files and short-circuits.
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --sysconfdir=/etc/ssh \
            --with-ssl-dir=${openssl} \
            --with-zlib=${zlib} \
            --with-privsep-path=/var/empty \
            --with-privsep-user=sshd \
            --with-pam \
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
        # `make install-nokeys` mirrors `install` but skips the
        # `install-sysconf-keys` hook that runs `ssh-keygen -A` during
        # the build. Without it, the package would ship the same host
        # keys to every AOS install — a critical security problem, and
        # also the reason `sshd-keygen.service` couldn't regenerate them
        # at runtime (the compiled-in default saw the store's pre-staged
        # keys as already-present). Pair with `--sysconfdir=/etc/ssh`
        # above so the produced ssh tools write to the runtime config
        # dir, not the (read-only) store path.
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            sed -i 's/-m 4711/-m 0755/g' Makefile
            # DESTDIR redirects all install paths under $out, so the
            # `install-sysconf` hook creates $out/etc/ssh/ (writable Nix
            # build dir) rather than /etc/ssh/ (which only exists on the
            # running system). Runtime binaries still look at /etc/ssh/
            # because that's what was compiled in via --sysconfdir above.
            make install-nokeys DESTDIR=$out
            # Flatten $out/$out/... back to $out (DESTDIR concatenates).
            cp -a $out$out/. $out/
            rm -rf $out/nix

            # Portable OpenSSH keeps ssh-copy-id in contrib and does not add
            # it to install-nokeys. Install the client helper explicitly so
            # the Darwin package has the complete command-line tool set.
            mkdir -p "$out/share/man/man1"
            install -m 0755 contrib/ssh-copy-id "$out/bin/ssh-copy-id"
            install -m 0644 contrib/ssh-copy-id.1 "$out/share/man/man1/ssh-copy-id.1"
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/ssh-copy-id"
          ''
          else ''
            sed -i 's/-m 4711/-m 0755/g' Makefile
            # DESTDIR redirects all install paths under $out, so the
            # `install-sysconf` hook creates $out/etc/ssh/ (writable Nix
            # build dir) rather than /etc/ssh/ (which only exists on the
            # running system). Runtime binaries still look at /etc/ssh/
            # because that's what was compiled in via --sysconfdir above.
            make install-nokeys DESTDIR=$out
            # Flatten $out/$out/... back to $out (DESTDIR concatenates).
            cp -a $out$out/. $out/
            rm -rf $out/nix
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

      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["ssh"];
      };

      config-validity = testing.mkVMTest {
        name = "cross-cutting-openssh-config-validity";
        rootfsDeps = [self];
        testScript = ''
          export PATH="${self}/bin:${self}/sbin:$PATH"

          echo "==> Testing sshd config parsing"
          mkdir -p /tmp/sshd_test /run/sshd /var/empty
          echo 'sshd:x:198:198:OpenSSH Privilege Separation:/var/empty:/sbin/nologin' >> /etc/passwd
          echo 'sshd:x:198:' >> /etc/group
          cat > /tmp/sshd_test/sshd_config << 'SSHCFG'
          Port 2222
          PermitRootLogin no
          PasswordAuthentication no
          PubkeyAuthentication yes
          SSHCFG

          ssh-keygen -t ed25519 -f /tmp/sshd_test/host_key -N "" -q
          echo "HostKey /tmp/sshd_test/host_key" >> /tmp/sshd_test/sshd_config
          sshd -t -f /tmp/sshd_test/sshd_config
          echo "    sshd config: valid"
          echo "OpenSSH config validity: PASS"
        '';
      };
    };
  }
