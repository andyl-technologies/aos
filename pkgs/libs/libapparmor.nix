##! libapparmor — AppArmor policy interaction library
{
  lib,
  mkDerivation,
  fetchurl,
  patch,
  autoconf,
  autoconf-archive,
  automake,
  libtool,
  gnumake,
  pkg-config,
  flex,
  bison,
  swig,
  perl,
  python3,
  setuptools,
  ncurses,
  libxcrypt,
  stdenv,
}: let
  version = "4.1.7";
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "libapparmor";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser returns the qualification label and enforce mode.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libapparmor primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libapparmor rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <sys/apparmor.h>\nint main(void) {\n    char confinement[] = \"qualification (enforce)\"; char *mode = NULL;\n    char *label = aa_splitcon(confinement, &mode);\n    return label != NULL && mode != NULL\n        && strcmp(label, \"qualification\") == 0 && strcmp(mode, \"enforce\") == 0 ? pass() : 2;\n}\n\n";
        };
        "input" = "An AppArmor confinement string containing an enforce mode suffix.";
        "operation" = "Split the label and mode through aa_splitcon.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lapparmor"
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
              "exact" = "libapparmor primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libapparmor rejects the pathname with a nonzero filesystem error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libapparmor primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libapparmor rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <fcntl.h>\n#include <sys/apparmor.h>\nint main(void) {\n    aa_features *features = NULL;\n    int status = aa_features_new(&features, AT_FDCWD, \"missing-qualification-features\");\n    if (features != NULL) aa_features_unref(features);\n    if (status == 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A feature-directory pathname that does not exist.";
        "operation" = "Open the missing feature description through aa_features_new.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lapparmor"
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
              "exact" = "libapparmor rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    outputs = ["out" "python" "perl"];
    src = fetchurl {
      urls = ["https://gitlab.com/apparmor/apparmor/-/archive/v${version}/apparmor-v${version}.tar.gz"];
      hash = "sha256-3tTNQZuKBQAqEIoJEiCOIJhpV1JmTGpZRk0t2kGOBFI=";
    };
    buildDeps = [
      patch
      autoconf
      autoconf-archive
      automake
      libtool
      gnumake
      pkg-config
      flex
      bison
      swig
      perl
      python3
      setuptools
      ncurses
    ];
    runtimeDeps = [libxcrypt];
    propagatedDeps = [libxcrypt];
    outputChecks.out.disallowedReferences = [python3 perl];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd apparmor-v${version}/libraries/libapparmor
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's/install_vendor/install_site/' swig/perl/Makefile.am
          patch -p1 < ${./libapparmor-swig-copy.patch}
        '';
      }
      {
        name = "configure";
        script =
          (
            if stdenv.isCross
            then ''
              # Binding suffixes, headers, and install paths belong to the target
              # interpreters. They run through the configured process emulator.
              export PYTHON=${python3}/bin/python3
              export PYTHON_CONFIG=${python3}/bin/python3-config
              export PERL=${perl}/bin/perl
            ''
            else ""
          )
          + ''
            export ACLOCAL_PATH="${autoconf-archive}/share/aclocal:${libtool}/share/aclocal:${pkg-config}/share/aclocal"
            export PYTHONPATH=${setuptools}/lib/python3.14/site-packages
            autoreconf -fiv
            ./configure $configureFlags \
              --prefix="$out" \
              --with-perl \
              --with-python
          '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          # The legacy parser harness requires Expect, which does not support
          # Tcl 9. Build its test executable and validate the language bindings
          # after installation instead.
          make -C testsuite test_multi.multi
        '';
      }
      {
        name = "install";
        script =
          ''
            make install
            test -f "$out/lib/libapparmor.so"

            mkdir -p "$python/lib" "$perl/lib"
            mv "$out/lib/python3.14" "$python/lib/"
            mv "$out/lib/perl5" "$out/lib/site_perl" "$perl/lib/"

            python_path=$(find "$python" -type d -name site-packages -print -quit)
            test -n "$python_path"
            PYTHONPATH="$python_path" ${python3}/bin/python3 -c 'import LibAppArmor'
          ''
          + (
            if stdenv.isCross
            then ''
              perl_path=$(find "$perl" -type f -name LibAppArmor.pm -print -quit)
              test -n "$perl_path"
              PERL5LIB="''${perl_path%/*}" ${perl}/bin/perl -MLibAppArmor -e 1
            ''
            else ""
          );
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-libapparmor";
        library = self;
        libs = ["-lapparmor"];
        testSource = ''
          #include <sys/apparmor.h>
          int main(void) {
            return aa_is_enabled() < 0;
          }
        '';
      };
    };
    meta = {
      description = "Library for querying and changing AppArmor confinement";
      homepage = "https://apparmor.net/";
      license = "LGPL-2.1-only AND GPL-2.0-only";
    };
  }
