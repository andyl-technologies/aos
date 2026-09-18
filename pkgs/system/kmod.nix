##! kmod — Linux kernel module handling
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  openssl,
  jansson,
  zlib,
  xz,
  zstd,
  stdenv,
}: let
  version = "34";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "kmod";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libkmod returns an object retaining the exact module name.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"kmod primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"kmod rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <libkmod.h>\nint main(void) {\n    struct kmod_ctx *context = kmod_new(NULL, NULL);\n    struct kmod_module *module = NULL;\n    if (context == NULL) return 2;\n    int status = kmod_module_new_from_name(context, \"loop\", &module);\n    int valid = status == 0 && module != NULL\n        && strcmp(kmod_module_get_name(module), \"loop\") == 0;\n    if (module != NULL) kmod_module_unref(module);\n    kmod_unref(context);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "The syntactically valid kernel module name loop.";
        "operation" = "Construct and inspect a module object through libkmod.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lkmod"
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
              "exact" = "kmod primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libkmod returns ENOENT and no module object.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"kmod primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"kmod rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <errno.h>\n#include <libkmod.h>\nint main(void) {\n    struct kmod_ctx *context = kmod_new(NULL, NULL);\n    struct kmod_module *module = NULL;\n    if (context == NULL) return 2;\n    int status = kmod_module_new_from_path(context, \"missing-qualification.ko\", &module);\n    if (module != NULL) kmod_module_unref(module);\n    kmod_unref(context);\n    return status == -ENOENT && module == NULL ? reject() : 3;\n}\n\n";
        };
        "input" = "A kernel module path that does not exist.";
        "operation" = "Construct a module from the missing path through libkmod.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lkmod"
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
              "exact" = "kmod rejected invalid input\n";
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
        # kernel.org retired /pub/linux/utils/kernel/kmod/ (kmod moved
        # to github.com/kmod-project, which publishes no dist tarball
        # assets); the whole directory 404s now. The cgit snapshot
        # service still serves per-tag archives (same source nixpkgs
        # uses), and kmod >= 33 is meson-native so the git tree builds
        # like the dist tarball.
        "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git/snapshot/kmod-${version}.tar.gz"
      ];
      hash = "sha256-y0e+STZrWW5FVO7rdZWxKP6yYWGcdnVgPgBLB8XrvVs=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
    ];
    runtimeDeps = [
      openssl
      jansson
      zlib
      xz
      zstd
    ];
    propagatedDeps = [
      openssl
      zlib
      xz
      zstd
    ];

    abilities = ./_kmod-abilities;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd kmod-${version}
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Bootstrap XZ also provides liblzma.pc. Resolve target libraries
            # before build-tool metadata so Meson never links a native archive.
            export PKG_CONFIG_PATH="${lib.makeSearchPath "lib/pkgconfig" [openssl zlib xz zstd]}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            # Meson removes inferred build RPATHs during installation. Keep
            # the cross wrapper's declared runtime paths as explicit flags.
            export LDFLAGS="$NIX_LDFLAGS ''${LDFLAGS:-}"
          ''
          + ''
            nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
            export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
            meson setup build \
              $mesonFlags \
              --prefix=$out \
              --sysconfdir=$out/etc \
              -Ddistconfdir=$out/lib \
              -Dzlib=enabled \
              -Dxz=enabled \
              -Dzstd=enabled \
              -Dmanpages=false \
              -Dbashcompletiondir=no
          '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          ninja -C build install

          mkdir -p $out/libexec
          cc -std=c11 -Wall -Wextra -Werror -O2 \
            ${./_kmod-handler.c} \
            -o $out/libexec/aos-kmod-handler \
            -ljansson -lcrypto
        '';
      }
    ];

    meta = {
      description = "kmod — Linux kernel module handling tools";
      homepage = "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git";
      license = "LGPL-2.1-or-later";
    };
  }
