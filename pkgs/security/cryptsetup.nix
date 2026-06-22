##! cryptsetup — LUKS / dm-crypt userspace tools and library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  device-mapper,
  popt,
  util-linux,
  json-c,
  openssl,
}: let
  version = "2.8.4";
  majorMinor = "2.8";
in
  mkDerivation {
    pname = "cryptsetup";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.kernel.org/pub/linux/utils/cryptsetup/v${majorMinor}/cryptsetup-${version}.tar.xz"
        "https://mirrors.kernel.org/linux/utils/cryptsetup/v${majorMinor}/cryptsetup-${version}.tar.xz"
      ];
      hash = "sha256-RD5G+JZMmsx4D0Va+7jiOqDo7X7FBM/FngT0BvoeioM=";
    };

    patches = [
      ./cryptsetup-patches/0001-fail-closed-on-signed-verity-activation.patch
    ];

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      device-mapper
      popt
      util-linux
      json-c
      openssl
    ];
    # libcryptsetup.pc has `Requires.private: uuid devmapper json-c openssl
    # blkid`, so downstream pkg-config consumers (e.g. systemd's meson
    # libcryptsetup probe) need those .pc files on their PKG_CONFIG_PATH.
    # uuid/blkid come from util-linux and openssl is commonly a direct dep
    # of cryptsetup's consumers, so only device-mapper and json-c need to
    # be propagated here — transitive collection
    # (lib/derivations.nix:collectPropagated) then reaches them.
    propagatedDeps = [
      device-mapper
      json-c
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cryptsetup-${version}
        '';
      }
      {
        name = "patch-source";
        script = ''
          # tests/generate-symbols-list is invoked during `make all` to
          # generate a C header from lib/libcryptsetup.sym. Its shebang
          # is /bin/bash which doesn't exist in the Nix sandbox — rewrite
          # to $CONFIG_SHELL (bootstrap bash) so the build can proceed.
          sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" tests/generate-symbols-list
        '';
      }
      {
        name = "configure";
        script = ''
          # Argon2 comes from OpenSSL's KDF provider (openssl ≥ 3.2).
          # AOS ships openssl 3.4.1, so configure.ac's probe for
          # OSSL_KDF_PARAM_ARGON2_VERSION succeeds and sets
          # use_internal_argon2=0. Do NOT pass --enable-libargon2 —
          # configure.ac's AC_MSG_ERROR would reject it.
          # External LUKS2 token plugins (e.g. systemd's
          # libcryptsetup-token-systemd-tpm2.so) are dlopen'd by ABSOLUTE
          # path from this dir — and the systemd-tpm2 plugin lives in
          # systemd's store path, not cryptsetup's. Point the search at a
          # runtime dir so a consumer (the measured-boot /var unlock) can
          # symlink the systemd plugin into it; LD_LIBRARY_PATH does not
          # affect this absolute-path dlopen. (RFC-0006 phase 3.)
          ./configure \
            --prefix=$out \
            --disable-static \
            --disable-asciidoc \
            --disable-ssh-token \
            --disable-nls \
            --disable-selinux \
            --with-crypto_backend=openssl \
            --with-luks2-external-tokens-path=/run/cryptsetup/tokens \
            --with-tmpfilesdir=$out/lib/tmpfiles.d
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        # `make install` (install-data-local) tries to mkdir the external
        # tokens path /run/cryptsetup/tokens, which is absolute and outside
        # $out — it fails in the sandbox. Install through a staging DESTDIR
        # so that absolute mkdir lands harmlessly in the stage, then copy
        # just the $out subtree back. (The real /run dir is created at boot
        # by the consumer.)
        name = "install";
        script = ''
          stage=$TMPDIR/cs-stage
          make install DESTDIR="$stage"
          mkdir -p $out
          cp -a "$stage$out/." $out/
        '';
      }
      {
        name = "sanity-check";
        script = ''
          $out/sbin/cryptsetup --version
          # Fail loudly if the openssl Argon2 backend isn't wired up —
          # this catches the "openssl downgraded below 3.2" failure mode
          # at build time rather than at first LUKS unlock.
          if [ -r /dev/urandom ]; then
            $out/sbin/cryptsetup benchmark --pbkdf argon2id || {
              echo "ERROR: argon2id benchmark failed — openssl Argon2 KDF may not be available"
              exit 1
            }
          fi
        '';
      }
    ];

    meta = {
      description = "LUKS / dm-crypt userspace tools and library";
      homepage = "https://gitlab.com/cryptsetup/cryptsetup";
      license = "GPL-2.0-or-later";
    };
  }
