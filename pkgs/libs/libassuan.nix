##! libassuan — IPC library implementing the Assuan protocol used by GnuPG
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
}: let
  version = "3.0.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libassuan";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libassuan returns a usable context without an error.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libassuan primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libassuan rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <assuan.h>\n\nint main(void) {\n    assuan_context_t context = NULL;\n    gpg_error_t status = assuan_new(&context);\n    int valid = status == 0 && context != NULL;\n    if (context != NULL) assuan_release(context);\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "A newly allocated Assuan context.";
        "operation" = "Create and release it through the public context API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lassuan\",\"-lgpg-error\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libassuan primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libassuan returns an error instead of establishing a connection.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libassuan primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libassuan rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <assuan.h>\n\nint main(void) {\n    assuan_context_t context = NULL;\n    if (assuan_new(&context) != 0 || context == NULL) return 2;\n    gpg_error_t status = assuan_socket_connect(\n        context,\n        \"missing-qualification.sock\",\n        ASSUAN_INVALID_PID,\n        0\n    );\n    assuan_release(context);\n    return status != 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "A request to connect to a Unix socket path that does not exist.";
        "operation" = "Open the missing endpoint through assuan_socket_connect.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lassuan\",\"-lgpg-error\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libassuan rejected invalid input\n";
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
        "https://gnupg.org/ftp/gcrypt/libassuan/libassuan-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libassuan/libassuan-${version}.tar.bz2"
      ];
      hash = "sha256-0pMc2tJm5jNRD5lw4aLzRgVeNRuxn5t4kSR1uAdMNvY=";
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

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libassuan-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # mkheader executes on the Linux build machine. Retain native
            # hardening, except for Darwin arm's target-only PAC mode, and
            # keep every target SDK/compiler flag out of its invocation.
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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/libassuan-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "IPC library implementing the Assuan protocol used by GnuPG";
      homepage = "https://gnupg.org/software/libassuan/";
      license = "LGPL-2.1-or-later";
    };
  }
