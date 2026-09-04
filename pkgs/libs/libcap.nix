##! libcap — POSIX capabilities library
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  linux-headers,
  binutils,
}: let
  version = "2.77";
in
  mkDerivation {
    pname = "libcap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
        "https://mirrors.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
      ];
      hash = "sha256-iXvBi0Svwmxw54zq09uzHhVKzCS+4IWloJB5qI2/b1I=";
    };

    buildDeps = [
      gnumake
      perl
      binutils
      # Kernel UAPI headers are compile-time only; in runtimeDeps they would
      # ride into the closure of everything that links libcap (a dead RPATH,
      # since linux-headers ships no shared library).
      linux-headers
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libcap-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Fix shebangs: scripts reference /bin/bash which doesn't exist
          # in the Nix sandbox. Replace with $CONFIG_SHELL (bootstrap bash).
          for f in $(find . -name '*.sh' -o -name '*.pl'); do
            if [ -f "$f" ]; then
              sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/env bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
            fi
          done

          build_cc=''${BUILD_CC:-$CC}

          make -j$NIX_BUILD_CORES \
            CC="$CC" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            OBJCOPY="${binutils}/bin/objcopy" \
            BUILD_CC="$build_cc" \
            prefix=$out \
            lib=lib \
            SHARED=yes \
            GOLANG=no \
            PAM_CAP=no \
            DYNAMIC=yes
        '';
      }
      {
        name = "install";
        script = ''
          build_cc=''${BUILD_CC:-$CC}

          make install \
            CC="$CC" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            OBJCOPY="${binutils}/bin/objcopy" \
            BUILD_CC="$build_cc" \
            prefix=$out \
            lib=lib \
            SHARED=yes \
            GOLANG=no \
            PAM_CAP=no \
            RAISE_SETFCAP=no \
            DYNAMIC=yes
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libcap";
        library = self;
        libs = ["-lcap"];
        testSource = ''
          #include <sys/capability.h>
          #include <stdio.h>
          int main() {
            cap_t caps = cap_get_proc();
            if (caps) {
              cap_free(caps);
            }
            printf("libcap: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libcap — POSIX capabilities library";
      homepage = "https://sites.google.com/site/fullaborern8/home";
      license = "BSD-3-Clause OR GPL-2.0-only";
    };
  }
