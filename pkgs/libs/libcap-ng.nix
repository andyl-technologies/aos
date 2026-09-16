##! libcap-ng — POSIX capability manipulation library
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  pkg-config,
  swig,
  python3,
  linux-headers,
  stdenv,
}: let
  version = "0.9.5";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "libcap-ng";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the CAP_CHOWN capability number.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libcap-ng primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libcap-ng rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <linux/capability.h>\n#include <cap-ng.h>\nint main(void) {\n    return capng_name_to_capability(\"chown\") == CAP_CHOWN ? pass() : 2;\n}\n\n";
        };
        "input" = "The canonical Linux capability name chown.";
        "operation" = "Resolve the name through capng_name_to_capability.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcap-ng"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libcap-ng primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libcap-ng rejects the name with a negative result.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libcap-ng primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libcap-ng rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <cap-ng.h>\nint main(void) {\n    if (capng_name_to_capability(\"qualification_capability_does_not_exist\") >= 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A capability name absent from Linux's capability registry.";
        "operation" = "Resolve the unknown name through capng_name_to_capability.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcap-ng"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libcap-ng rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    # Preserve the bindings separately from the library used by boot tools.
    outputs = ["out" "python"];
    src = fetchurl {
      urls = ["https://github.com/stevegrubb/libcap-ng/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-orQhH1myMdYHxh6ioT6eyzj0Rv52m0ThLak51a9tl4o=";
    };
    buildDeps = [autoconf automake libtool gnumake pkg-config swig python3 linux-headers];
    runtimeDeps = [python3];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libcap-ng-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          touch NEWS
          sed -i 's|/usr/bin/captest|captest|g' utils/captest.c
          sed -i \
            's|/usr/include/linux/capability.h|${linux-headers}/include/linux/capability.h|g' \
            bindings/python3/Makefile.am
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal:${pkg-config}/share/aclocal"
          autoreconf -fiv
          ./configure $configureFlags \
            --prefix="$out" \
            --with-python3 \
            PYTHON=${python3}/bin/python3
          sed -i \
            's|/usr/include/linux/capability.h|${linux-headers}/include/linux/capability.h|g' \
            bindings/python3/Makefile
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script =
          if stdenv.isCross
          then ''
            # Automake still builds every source test through check_PROGRAMS.
            # Run the tests whose assertions are independent of the emulated
            # process's kernel capability state; qemu-user cannot faithfully
            # expose capget/capset state for the remaining three tests.
            make -C src/test check TESTS="file_caps_test securebits_test"
            make -C utils check
            (
              cd bindings/python3/test
              PYTHONPATH=..:../.libs \
                LD_LIBRARY_PATH="$PWD/../../../src/.libs" \
                ${python3}/bin/python3 capng-test.py
            )
          ''
          else ''
            make -C src check
            make -C utils check
            (
              cd bindings/python3/test
              PYTHONPATH=..:../.libs \
                LD_LIBRARY_PATH="$PWD/../../../src/.libs" \
                ${python3}/bin/python3 capng-test.py
            )
          '';
      }
      {
        name = "install";
        script = ''
          make install
          mkdir -p "$python/lib"
          for bindings in "$out"/lib/python*; do
            test -d "$bindings"
            mv "$bindings" "$python/lib/"
          done
          python_path=$(find "$python/lib" -type d -name site-packages -print -quit)
          test -n "$python_path"
          PYTHONPATH="$python_path" ${python3}/bin/python3 -c 'import capng'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-libcap-ng";
        library = self;
        libs = ["-lcap-ng"];
        testSource = ''
          #include <cap-ng.h>
          int main(void) {
            capng_clear(CAPNG_SELECT_BOTH);
            return capng_have_capabilities(CAPNG_SELECT_BOTH) < 0;
          }
        '';
      };
    };
    meta = {
      description = "Library and utilities for working with POSIX capabilities";
      homepage = "https://github.com/stevegrubb/libcap-ng";
      license = "LGPL-2.1-only";
    };
  }
