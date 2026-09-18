##! libksba — X.509 and CMS (PKCS#7) library used by GnuPG's gpgsm
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
}: let
  version = "1.8.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libksba";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "KSBA returns the exact eight-byte payload.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libksba primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libksba rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <string.h>\n#include <ksba.h>\n\nint main(void) {\n    const char input[] = \"answer=42\";\n    char output[sizeof(input)] = {0};\n    size_t read_count = 0;\n    ksba_reader_t reader = NULL;\n    if (ksba_reader_new(&reader) != 0 || reader == NULL) return 2;\n    if (ksba_reader_set_mem(reader, input, sizeof(input) - 1) != 0) return 3;\n    gpg_error_t status = ksba_reader_read(reader, output, sizeof(input) - 1, &read_count);\n    int valid = status == 0\n        && read_count == sizeof(input) - 1\n        && memcmp(input, output, read_count) == 0;\n    ksba_reader_release(reader);\n    return valid ? pass() : 4;\n}\n\n";
        };
        "input" = "An in-memory KSBA reader containing the bytes answer=42.";
        "operation" = "Create the reader, assign its memory, and read the bytes back.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lksba\",\"-lgpg-error\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
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
              "exact" = "libksba primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "KSBA returns a parse error for the malformed certificate.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libksba primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libksba rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <stdio.h>\n#include <unistd.h>\n#include <ksba.h>\n\nint main(void) {\n    const char input[] = \"not DER\";\n    ksba_reader_t reader = NULL;\n    ksba_cert_t certificate = NULL;\n    if (ksba_reader_new(&reader) != 0 || reader == NULL) return 2;\n    if (ksba_reader_set_mem(reader, input, sizeof(input) - 1) != 0) return 3;\n    if (ksba_cert_new(&certificate) != 0 || certificate == NULL) return 4;\n\n    int saved_stderr = dup(fileno(stderr));\n    FILE *discard = fopen(\"/dev/null\", \"w\");\n    if (saved_stderr < 0 || discard == NULL) return 5;\n    if (dup2(fileno(discard), fileno(stderr)) < 0) return 6;\n    gpg_error_t status = ksba_cert_read_der(certificate, reader);\n    fflush(stderr);\n    if (dup2(saved_stderr, fileno(stderr)) < 0) return 8;\n    close(saved_stderr);\n    fclose(discard);\n\n    ksba_cert_release(certificate);\n    ksba_reader_release(reader);\n    return status != 0 ? reject() : 9;\n}\n\n";
        };
        "input" = "A short text payload that is not a DER certificate.";
        "operation" = "Read it through KSBA's DER certificate parser.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lksba\",\"-lgpg-error\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
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
              "exact" = "libksba rejected invalid input\n";
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
        "https://gnupg.org/ftp/gcrypt/libksba/libksba-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libksba/libksba-${version}.tar.bz2"
      ];
      hash = "sha256-wvhDkwEYJyGa4RcTHbqOdoTCvtCWHu0RsGQsKsukQLU=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [libgpg-error]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [libgpg-error];

    # The asn1-gentables build tool uses the classic struct hack — a trailing
    # `char name[1]` (src/asn1-gentables.c) that it over-allocates with
    # `xmalloc(sizeof *item + strlen(name))` and then strcpy's the full name
    # into. -fstrict-flex-arrays=3 treats `[1]` as exactly one byte, so
    # _FORTIFY_SOURCE's __strcpy_chk sees object size 1 and aborts ("buffer
    # overflow detected") while generating asn1-tables.c. Step down to level 1,
    # where `[1]` is still honoured as a flexible array; the rest of the
    # hardening (including fortify3) stays on. Mirrors the acl step-down.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libksba-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isLinux
        then [
          {
            name = "patch";
            script = ''
              # The native generator retains full strict-flex-array hardening.
              # Give its variable-length names an actual flexible array and
              # allocate the terminator explicitly instead of using char[1].
              sed -i \
                -e 's/char name\[1\];/char name[];/' \
                  -e 's/sizeof \*item + strlen (name)/sizeof *item + strlen (name) + 1/' \
                  src/asn1-gentables.c
                sed -i 's/char filename\[1\];/char filename[];/' src/asn1-func.h
                sed -i \
                  's/sizeof \*tree + (file_name? strlen (file_name):1)/sizeof *tree + (file_name? strlen (file_name):1) + 1/' \
                  src/asn1-parse.y src/asn1-parse.c
                sed -i \
                  's/sizeof \*tree + strlen (mod_name)/sizeof *tree + strlen (mod_name) + 1/' \
                  src/asn1-func2.c
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script =
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # asn1-gentables executes on the Linux build machine. Preserve
              # this package's flexible-array hardening workaround, but remove
              # the target-only arm PAC token and every target SDK/compiler flag.
              native_cc="$BUILD_CC"
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc-for-build <<EOF
              #!$CONFIG_SHELL
              native_hardening=
              for token in \$AOS_HARDENING_ENABLE; do
                case "\$token" in
                  pacret) ;;
                  *) native_hardening="\$native_hardening \$token" ;;
                esac
              done
              export AOS_HARDENING_ENABLE="\$native_hardening"
              unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc-for-build
              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"

              # gpgrt-config is a target shell script. Execute it with the native
              # configure shell while making it resolve the target .pc metadata.
              cat > .aos-build-tools/gpgrt-config <<EOF
              #!$CONFIG_SHELL
              exec "$CONFIG_SHELL" ${libgpg-error}/bin/gpgrt-config "\$@"
              EOF
              chmod +x .aos-build-tools/gpgrt-config
              export GPGRT_CONFIG="$PWD/.aos-build-tools/gpgrt-config"
              export PKG_CONFIG_LIBDIR=
              export PKG_CONFIG_PATH="${libgpg-error}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

              ./configure \
                $configureFlags \
                --prefix=$out \
                --disable-static \
                --with-libgpg-error-prefix=${libgpg-error}
            ''
            else ''
              # Recent libgpg-error releases provide gpgrt-config instead of
              # gpg-error-config; runtime dependencies are not on the build PATH.
              export GPGRT_CONFIG=${libgpg-error}/bin/gpgrt-config

              ./configure \
                $configureFlags \
                --prefix=$out \
                --disable-static \
                --with-libgpg-error-prefix=${libgpg-error}
            '';
        }
        {
          name = "build";
          script = ''
            make -j$NIX_BUILD_CORES
          '';
        }
        {
          name = "install";
          script =
            if stdenv.hostPlatform.isDarwin
            then ''
              make install
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/ksba-config"
            ''
            else ''
              make install
            '';
        }
      ];

    meta = {
      description = "X.509 and CMS (PKCS#7) library used by GnuPG's gpgsm";
      homepage = "https://gnupg.org/software/libksba/";
      license = "LGPL-3.0-or-later";
    };
  }
