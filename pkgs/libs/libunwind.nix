##! Local, remote, and core-dump stack unwinding.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  callPackage,
  stdenv,
  xz,
  zlib,
}: let
  version = "1.8.3";
  testCoreutils = callPackage ../tools/_device-test-coreutils.nix {};
in
  mkDerivation {
    pname = "libunwind";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libunwind/libunwind/releases/download/v${version}/libunwind-${version}.tar.gz"];
      hash = "02xr36mhmrkpzwhnn4ngi841lsijgwsz2c9jflpdhn3zwq8djc5y";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.latex2man buildPackages.xz];
    runtimeDeps = [xz zlib];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libunwind-${version}
            # C23 treats empty parameter lists as void; this callback is malloc.
            sed -i -e 's/(\*func)();/(*func)(size_t);/' \
              -e 's/(void \*(\*)())/(void *(*)(size_t))/' tests/Gtest-nomalloc.c
            find tests -type f -exec sed -i '1s|^#!/bin/sh$|#!${buildPackages.bash}/bin/bash|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            export SOURCE_DATE_EPOCH=1 TZ=UTC
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static \
              --enable-minidebuginfo --enable-zlibdebuginfo --enable-documentation --enable-tests
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              # The remote unwinding test traces ls through its libc frames.
              export PATH="${testCoreutils}/bin:$PATH"
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libunwind"
            cp COPYING "$out/share/licenses/libunwind/"
          '';
        }
      ];
    meta = {
      description = "Local, remote, and core-dump stack unwinding";
      homepage = "https://github.com/libunwind/libunwind";
      license = "MIT";
    };
  }
