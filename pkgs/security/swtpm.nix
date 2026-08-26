{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  gettext,
  perl,
  python3,
  bash,
  libtpms,
  glib,
  json-glib,
  gnutls,
  libtasn1,
  libseccomp,
  openssl,
  stdenv,
}: let
  version = "0.10.0";
in
  mkDerivation {
    pname = "swtpm";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/stefanberger/swtpm/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-nxCuDTEjqwXDgI+MjTn2M88aDPFC1qybh7g2SmgqyEI=";
    };

    buildDeps = [
      gnumake
      pkg-config
      autoconf
      automake
      libtool
      gettext
      perl
      python3
      glib.dev
      glib.tools
    ];
    runtimeDeps =
      [
        libtpms
        glib
        json-glib
        gnutls
        libtasn1
        openssl
        bash
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [libseccomp]
      );
    propagatedDeps = [libtpms];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd swtpm-${version}
          # `make install` executes helper scripts (notably fileinstall), so
          # they must use the native shell while cross-compiling.  Installed
          # scripts are retargeted to the Darwin Bash after installation.
          grep -rlZ \
            -e '^#!/usr/bin/env bash' \
            -e '^#!/usr/bin/env sh' \
            -e '^#!/bin/bash' \
            -e '^#!/bin/sh' \
            . 2>/dev/null \
            | while IFS= read -r -d "" f; do
              sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$f"
            done
        '';
      }
      {
        # GitHub archive: regenerate the build system. swtpm has a po/
        # gettext catalogue, so autopoint (gettext) must be on PATH and in
        # ACLOCAL_PATH alongside pkg.m4 and libtool's macros. CUSE needs
        # libfuse we do not ship — the QEMU vTPM uses socket mode, so
        # --without-cuse. --with-openssl makes swtpm's own crypto use
        # libcrypto (gnutls stays only for the certificate tooling).
        name = "configure";
        script = ''
          nativePkgConfig=$(dirname "$(dirname "$(command -v pkg-config)")")
          nativeLibtool=$(dirname "$(dirname "$(command -v libtoolize)")")
          nativeGettext=$(dirname "$(dirname "$(command -v autopoint)")")
          export ACLOCAL_PATH="$nativePkgConfig/share/aclocal:$nativeLibtool/share/aclocal:$nativeGettext/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          # swtpm's configure hard-requires several tools purely for its
          # test suite (make check) — expect, socat, ss/netstat — which we
          # never run in the hermetic build. Shim them so configure passes
          # without pulling in Tcl/expect and friends.
          mkdir -p $TMPDIR/fakebin
          for t in expect socat netstat ss; do
            printf '#!%s\nexit 0\n' "$CONFIG_SHELL" > $TMPDIR/fakebin/$t
            chmod +x $TMPDIR/fakebin/$t
          done
          export PATH=$TMPDIR/fakebin:$PATH
          NOCONFIGURE=1 ./autogen.sh
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --without-cuse \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--without-seccomp --without-selinux"
            else ""
          } \
            --with-openssl \
            --with-tss-user=root \
            --with-tss-group=root
        '';
      }
      {
        # swtpm also compiles with -Werror; demote under GCC 14 the same
        # way as libtpms.
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES CFLAGS="-O2 -g -Wno-error"
        '';
      }
      {
        name = "install";
        script = ''
          make install
          grep -rlZ "^#!$CONFIG_SHELL" "$out" 2>/dev/null \
            | while IFS= read -r -d "" f; do
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
            done
        '';
      }
    ];

    meta = {
      description = "Software TPM emulator (libtpms-backed) for QEMU vTPM";
      homepage = "https://github.com/stefanberger/swtpm";
      license = "BSD-3-Clause";
    };
  }
