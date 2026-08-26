##! Boost — Free peer-reviewed portable C++ source libraries
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  which,
  bzip2,
  zlib,
  buildPackages,
  stdenv,
}: let
  version = "1.87.0";
  underscoreVersion = "1_87_0";
in
  mkDerivation {
    pname = "boost";
    inherit version;

    # Split outputs: `out` (default) carries only the shared libraries
    # (~5 MiB); `dev` carries the headers and CMake package files (~90 MiB).
    # Boost is overwhelmingly headers, so a consumer that only links it at
    # runtime (nix) keeps the header tree out of its runtime closure by using
    # `boost` for libs and `boost.dev` for build-time includes.
    outputs = ["out" "dev" "tools"];

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
          # Build helpers must use the native shell.  A cross build cannot
          # execute the Bash that belongs in the Darwin target package set.
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/usr/bin/env sh|#!$CONFIG_SHELL|"
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/usr/bin/env bash|#!$CONFIG_SHELL|"
          find . -type f \( -name "*.sh" -o -name "bootstrap*" \) -print0 | \
            xargs -0 sed -i "1s|^#!/bin/bash|#!$CONFIG_SHELL|"

          ${
            if stdenv.isCross
            then ''
              cp ${buildPackages.boost.tools}/bin/b2 ./b2
              cat > user-config.jam <<EOF
              using clang : : ${stdenv.cc}/bin/clang++ ;
              EOF
            ''
            else ''
              "$CONFIG_SHELL" ./bootstrap.sh \
                --prefix=$out \
                --with-libraries=system,filesystem,regex,container,context,coroutine,thread,chrono,date_time,program_options,iostreams,serialization,log,atomic,random \
                --with-toolset=gcc
            ''
          }
        '';
      }
      {
        name = "build";
        script = ''
          ./b2 -j$NIX_BUILD_CORES \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--user-config=$PWD/user-config.jam toolset=clang"
            else "toolset=gcc"
          } \
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
          # Headers -> $dev/include, shared libraries -> $out/lib. With
          # link=shared b2 builds no static archives, so $out/lib holds only
          # the .so set; the CMake package files are build-time only and are
          # moved into $dev so the runtime lib output references nothing in it.
          ./b2 install \
            --prefix=$dev \
            --includedir=$dev/include \
            --libdir=$out/lib \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--user-config=$PWD/user-config.jam toolset=clang"
            else "toolset=gcc"
          } \
            variant=release \
            link=shared \
            runtime-link=shared \
            threading=multi

          if [ -d "$out/lib/cmake" ]; then
            mkdir -p "$dev/lib"
            mv "$out/lib/cmake" "$dev/lib/cmake"
          fi

          mkdir -p "$tools/bin"
          if [ -z "''${AOS_CROSS_COMPILING:-}" ]; then
            cp ./b2 "$tools/bin/b2"
          fi
        '';
      }
    ];

    meta = {
      description = "Boost — free peer-reviewed portable C++ source libraries";
      homepage = "https://www.boost.org";
      license = "BSL-1.0";
    };
  }
