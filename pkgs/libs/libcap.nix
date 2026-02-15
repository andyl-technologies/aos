##! libcap — POSIX capabilities library
{
  mkDerivation,
  fetchurl,
  make,
  perl,
  linux-headers,
  binutils,
}:

let
  version = "2.70";
in
mkDerivation {
  pname = "libcap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.edge.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
      "https://mirrors.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
    ];
    hash = "sha256-I6bviq2vHj6HX2M7stEWz++JUtunvHxWmxNFjhlSsw8=";
  };

  buildDeps = [
    make
    perl
    binutils
  ];
  runtimeDeps = [ linux-headers ];
  propagatedDeps = [ ];

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

        make -j$NIX_BUILD_CORES \
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
        make install \
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

  meta = {
    description = "libcap — POSIX capabilities library";
    homepage = "https://sites.google.com/site/fullaborern8/home";
    license = "BSD-3-Clause OR GPL-2.0-only";
  };
}
