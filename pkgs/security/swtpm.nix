{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  m4,
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
  buildPackages,
}: let
  version = "0.10.2";
  isCross = stdenv.isCross;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "swtpm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Swtpm-setup creates all three nonempty configuration files below the requested directory.";
        "files" = {};
        "input" = "An empty per-user configuration directory.";
        "operation" = "Generate the default swtpm setup and local-CA configuration files.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import os, pathlib, subprocess\nconfig = pathlib.Path(\"config\").resolve()\nenvironment = os.environ.copy()\nenvironment[\"XDG_CONFIG_HOME\"] = str(config)\nresult = subprocess.run([\"@out@/bin/swtpm_setup\", \"--create-config-files\", \"skip-if-exist\"], env=environment, capture_output=True)\nassert result.returncode == 0, result.stderr\nnames = [\"swtpm_setup.conf\", \"swtpm-localca.conf\", \"swtpm-localca.options\"]\nassert all((config / name).stat().st_size > 0 for name in names)\nprint(\"swtpm operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "swtpm operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Swtpm-setup rejects the unknown option before creating TPM state.";
        "files" = {};
        "input" = "An option not recognized by swtpm-setup.";
        "operation" = "Parse the invalid setup invocation.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/swtpm_setup\", \"--qualification-invalid\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unrecognized option\" in result.stderr\n\nsys.stderr.write(\"swtpm rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "swtpm rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/stefanberger/swtpm/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-9hz28em7y0zvswtwyvrxxN9UxpYeZc+mODDorQ4iATQ=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
        autoconf
        automake
        libtool
        m4
        gettext
        perl
        python3
      ]
      ++ (
        if isCross
        then [buildPackages.glib.tools]
        else [glib.dev glib.tools]
      );
    runtimeDeps =
      [
        libtpms
        glib
        json-glib
        gnutls
        libtasn1
        openssl
        bash
        python3
      ]
      ++ (
        # GLib generators run on the build machine, but swtpm compiles and
        # links against the target headers and package metadata.
        if isCross
        then [glib.dev]
        else []
      )
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
          # scripts are retargeted to the selected Bash after installation.
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
          grep -rlZ \
            -e '^#!/usr/bin/env python3' \
            -e '^#!/usr/bin/python3' \
            "$out" 2>/dev/null \
            | while IFS= read -r -d "" f; do
              sed -i "1s|^#!.*|#!${python3}/bin/python3|" "$f"
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
