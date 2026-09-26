##! Local, remote, and core-dump stack unwinding.
{
  lib,
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
    pname = "libunwind";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The current process stack.";
        operation = "Capture a local unwind cursor and advance to its caller.";
        expected = "The cursor exposes a nonzero instruction pointer and a caller frame.";
        files."stack.c" = ''
          #define UNW_LOCAL_ONLY
          #include <libunwind.h>
          #include <stdio.h>

          int main(void) {
            unw_context_t context;
            unw_cursor_t cursor;
            unw_word_t instruction_pointer = 0;
            if (unw_getcontext(&context) < 0) return 1;
            if (unw_init_local(&cursor, &context) < 0) return 2;
            if (unw_get_reg(&cursor, UNW_REG_IP, &instruction_pointer) < 0 ||
                instruction_pointer == 0) return 3;
            if (unw_step(&cursor) <= 0) return 4;

            puts("libunwind local stack traversal passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "stack.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lunwind"
              "-o"
              "stack"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./stack"];
            exit_code = 0;
            stdout.exact = "libunwind local stack traversal passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An invalid register number in an otherwise valid local cursor.";
        operation = "Read that register through the unwind API.";
        expected = "The API returns its bad-register error.";
        files."bad.c" = ''
          #define UNW_LOCAL_ONLY
          #include <libunwind.h>
          #include <stdio.h>

          int main(void) {
            unw_context_t context;
            unw_cursor_t cursor;
            unw_word_t value = 0;
            if (unw_getcontext(&context) < 0 ||
                unw_init_local(&cursor, &context) < 0) return 1;
            if (unw_get_reg(&cursor, (unw_regnum_t)123456, &value) != -UNW_EBADREG)
              return 2;

            puts("libunwind rejected invalid register");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "bad.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lunwind"
              "-o"
              "bad"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./bad"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "libunwind rejected invalid register\n";
            stderr.exact = "";
          }
        ];
      };
    };
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
