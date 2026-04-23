##! Boost — Free peer-reviewed portable C++ source libraries
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  which,
  bzip2,
  zlib,
}: let
  version = "1.87.0";
  underscoreVersion = "1_87_0";
in
  mkDerivation {
    pname = "boost";
    inherit version;

    src = fetchurl {
      urls = [
        "https://archives.boost.io/release/${version}/source/boost_${underscoreVersion}.tar.bz2"
      ];
      hash = "sha256-r1e+JctMT0tBPtaS/jeK/7Q1LqUPvilKEe9Uj01SfYk=";
    };

    buildDeps = [
      gnumake
      bash
      which
    ];
    runtimeDeps = [
      bzip2
      zlib
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd boost_${underscoreVersion}
        '';
      }
      {
        name = "configure";
        script = ''
          # Patch shebangs: /usr/bin/env doesn't exist in the Nix sandbox
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/usr/bin/env sh|#!/bin/sh|"
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/usr/bin/env bash|#!${bash}/bin/bash|"
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/bin/bash|#!${bash}/bin/bash|"

          ${bash}/bin/bash ./bootstrap.sh \
            --prefix=$out \
            --with-libraries=system,filesystem,regex,container,context,coroutine,thread,chrono,date_time,program_options,iostreams,serialization,log,atomic,random \
            --with-toolset=gcc
        '';
      }
      {
        name = "build";
        script = ''
          ./b2 -j$NIX_BUILD_CORES \
            toolset=gcc \
            variant=release \
            link=shared \
            runtime-link=shared \
            threading=multi \
            --prefix=$out \
            -sZLIB_INCLUDE=${zlib}/include \
            -sZLIB_LIBRARY_PATH=${zlib}/lib \
            -sBZIP2_INCLUDE=${bzip2}/include \
            -sBZIP2_LIBRARY_PATH=${bzip2}/lib
        '';
      }
      {
        name = "install";
        script = ''
          ./b2 install \
            --prefix=$out \
            toolset=gcc \
            variant=release \
            link=shared \
            runtime-link=shared \
            threading=multi
        '';
      }
    ];

    meta = {
      description = "Boost — free peer-reviewed portable C++ source libraries";
      homepage = "https://www.boost.org";
      license = "BSL-1.0";
    };
  }
