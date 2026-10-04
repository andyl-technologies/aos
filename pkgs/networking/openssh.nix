##! OpenSSH — Secure shell client and server
{
  lib,
  mkDerivation,
  aos-runtime-checks,
  fetchurl,
  gnumake,
  linux-pam,
  libxcrypt,
  openpam,
  openssl,
  zlib,
  bash,
  stdenv,
  service-management,
  aos-filesystem-provider,
  nftables,
}: let
  version = "10.5p1";
  configureFor = prefix: ''
    ./configure \
      $configureFlags \
      --prefix="${prefix}" \
      --sysconfdir=/etc/ssh \
      --with-ssl-dir=${openssl} \
      --with-zlib=${zlib} \
      --with-privsep-path=/var/empty \
      --with-privsep-user=sshd \
      --with-pam \
      --disable-strip
  '';
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "openssh";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Both key generation and private-key parsing succeed.";
        "files" = {};
        "input" = "A request for a passphrase-protected Ed25519 private key in the probe workspace.";
        "operation" = "Generate the key and derive its public key through ssh-keygen.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/ssh-keygen"
              "-q"
              "-t"
              "ed25519"
              "-N"
              "qualification-passphrase"
              "-f"
              "qualification-key"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/ssh-keygen"
              "-y"
              "-P"
              "qualification-passphrase"
              "-f"
              "qualification-key"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "ssh-keygen rejects the file with its key-load failure status.";
        "files" = {
          "invalid" = "not an OpenSSH private key\n";
        };
        "input" = "A text file that is not an OpenSSH private key.";
        "operation" = "Attempt to derive a public key from the malformed file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/ssh-keygen"
              "-y"
              "-f"
              "invalid"
            ];
            "exit_code" = 255;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;
    outputs = ["out" "server"];

    src = fetchurl {
      urls = [
        "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${version}.tar.gz"
      ];
      hash = "sha256-1E0oqDnqna+WnMaRUP3lmRCys5Nh2tgaO9bL0ZIY2xE=";
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
        # OpenSSH links crypt directly; PAM's dependency does not preserve
        # that library's runtime path through the reference scrub phase.
        else [libxcrypt]
      );
    propagatedDeps = [];

    module = ./_openssh;
    moduleDeps = [aos-runtime-checks service-management aos-filesystem-provider nftables linux-pam];

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
        script = configureFor "$out";
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
      {
        name = "build-server-output";
        # A second build gives daemon helpers and key generation their own
        # immutable prefix. Moving binaries from out would retain client paths.
        script = ''
          make distclean
          ${configureFor "$server"}
          make -j$NIX_BUILD_CORES
          sed -i 's/-m 4711/-m 0755/g' Makefile
          make install-nokeys DESTDIR="$server"
          cp -a "$server$server/." "$server/"
          rm -rf "$server/nix"

          # Keep the server, its SFTP subsystem, and key-generation helpers.
          # The default output still exposes every installed upstream command.
          rm -f "$server/bin/ssh" "$server/bin/scp" "$server/bin/sftp" \
            "$server/bin/ssh-add" "$server/bin/ssh-agent" "$server/bin/ssh-keyscan" \
            "$server/libexec/ssh-keysign" "$server/etc/ssh/ssh_config"
          rm -f "$server/share/man/man1/ssh.1" "$server/share/man/man1/scp.1" \
            "$server/share/man/man1/sftp.1" "$server/share/man/man1/ssh-add.1" \
            "$server/share/man/man1/ssh-agent.1" "$server/share/man/man1/ssh-keyscan.1" \
            "$server/share/man/man5/ssh_config.5" "$server/share/man/man8/ssh-keysign.8"
        '';
      }
      {
        name = "install-service-helpers";
        script = ''
          for destination in "$out" "$server"; do
            mkdir -p "$destination/libexec"
            $CC -O2 -Wall -Wextra -Werror \
              "-DSSH_KEYGEN_PATH=\"$destination/bin/ssh-keygen\"" \
              -o "$destination/libexec/aos-openssh-host-key" \
              ${./_openssh/host-key-helper.c}
            $CC -O2 -Wall -Wextra -Werror \
              -o "$destination/libexec/aos-openssh-host-policy-wait" \
              ${./_openssh/host-policy-wait.c}
          done
        '';
      }
    ];

    meta = {
      description = "OpenSSH — secure shell connectivity tools";
      # The client suite and daemon payload have no shared executable entry point.
      mainProgram = null;
      homepage = "https://www.openssh.com";
      license = "BSD-2-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      server-output = pkgs.mkDerivation {
        pname = "openssh-server-output-check";
        inherit version;
        buildDeps = [self self.server pkgs.coreutils pkgs.diffutils];
        exportReferencesGraph = ["server-closure" self.server];
        phases = [
          {
            name = "check";
            script = ''
              while IFS= read -r entry; do
                test "$entry" != "${self}"
              done < server-closure
              for command in ssh scp sftp ssh-add ssh-agent ssh-keyscan ssh-keygen; do
                test -x "${self}/bin/$command"
              done
              for command in ssh scp sftp ssh-add ssh-agent ssh-keyscan; do
                test ! -e "${self.server}/bin/$command"
              done
              for helper in sshd-auth sshd-session sftp-server ssh-sk-helper ssh-pkcs11-helper aos-openssh-host-key aos-openssh-host-policy-wait; do
                test -x "${self.server}/libexec/$helper"
              done
              test -x "${self.server}/sbin/sshd"
              ${self}/bin/ssh -V
              ${self.server}/sbin/sshd -V
              ${self.server}/bin/ssh-keygen -q -t ed25519 -N probe-passphrase -f probe-key
              ${self.server}/bin/ssh-keygen -y -P probe-passphrase -f probe-key > derived-with-comment.pub
              cut -d ' ' -f 1,2 derived-with-comment.pub > derived.pub
              cut -d ' ' -f 1,2 probe-key.pub > expected.pub
              cmp derived.pub expected.pub
              mkdir -p "$out"
              printf 'PASS\n' > "$out/result"
            '';
          }
        ];
      };

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

      service-helpers = testing.mkVMTest {
        name = "tool-openssh-service-helpers";
        rootfsDeps = [self pkgs.coreutils];
        testScript = ''
          mkdir -p /var/etc/ssh /run/aos

          ${self}/libexec/aos-openssh-host-key
          test -s /var/etc/ssh/ssh_host_ed25519_key
          test -s /var/etc/ssh/ssh_host_ed25519_key.pub
          first_hash=$(sha256sum /var/etc/ssh/ssh_host_ed25519_key)
          ${self}/libexec/aos-openssh-host-key
          test "$first_hash" = "$(sha256sum /var/etc/ssh/ssh_host_ed25519_key)"

          touch /run/aos/host-policy-live
          ${self}/libexec/aos-openssh-host-policy-wait
        '';
      };

      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["ssh" "sshd" "/libexec/sshd-auth" "/libexec/sshd-session"];
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
