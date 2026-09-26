##! libslirp — General purpose TCP-IP emulator (user-mode networking for QEMU)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  glib,
  stdenv,
  buildPackages,
}: let
  version = "4.9.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libslirp";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The runtime version matches the public header and exposes a positive state version.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libslirp primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libslirp rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <slirp/libslirp.h>\nint main(void) {\n    int valid = strcmp(slirp_version_string(), SLIRP_VERSION_STRING) == 0\n        && slirp_state_version() > 0;\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "The linked libslirp implementation version.";
        "operation" = "Query its version string and state format version.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lslirp"
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
              "exact" = "libslirp primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libslirp rejects the configuration by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libslirp primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libslirp rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <fcntl.h>\n#include <unistd.h>\n#include <slirp/libslirp.h>\nint main(void) {\n    int saved_stderr = dup(STDERR_FILENO);\n    int null_output = open(\"/dev/null\", O_WRONLY);\n    if (saved_stderr < 0 || null_output < 0) return 2;\n    if (dup2(null_output, STDERR_FILENO) < 0) return 3;\n    SlirpConfig config = {.version = SLIRP_CONFIG_VERSION_MAX + 1};\n    SlirpCb callbacks = {0};\n    Slirp *slirp = slirp_new(&config, &callbacks, NULL);\n    fflush(stderr);\n    if (dup2(saved_stderr, STDERR_FILENO) < 0) return 4;\n    close(null_output);\n    close(saved_stderr);\n    if (slirp != NULL) {\n        slirp_cleanup(slirp);\n        return 5;\n    }\n    return reject();\n}\n\n";
        };
        "input" = "A Slirp configuration version above the supported maximum.";
        "operation" = "Construct a Slirp instance through slirp_new while suppressing its expected assertion log.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lslirp"
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
              "exact" = "libslirp rejected invalid input\n";
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
        "https://gitlab.freedesktop.org/slirp/libslirp/-/archive/v${version}/libslirp-v${version}.tar.gz"
      ];
      hash = "sha256-OZiGOwIK7aNL3cVnCXxu+6VaeM327u5rzULBHvI5Z9o=";
    };

    buildDeps =
      if stdenv.isCross
      then [
        buildPackages.gnumake
        buildPackages.pkg-config
        buildPackages.meson
        buildPackages.ninja
        buildPackages.python3
      ]
      else [
        gnumake
        pkg-config
        meson
        ninja
        python3
        glib.dev
        glib.tools
      ];
    runtimeDeps = [glib];
    propagatedDeps = [glib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libslirp-v${version}
          # libslirp derives its version from git via build-aux/git-version-gen.
          # When building from a tarball, drop the version into .tarball-version
          # so meson reads it instead of failing the git probe.
          echo ${version} > .tarball-version
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross
            then ''
              # Cross pkg-config must preserve absolute Nix store paths from
              # GLib's metadata. Provide the target include and split library
              # outputs explicitly while all Meson/Python tools stay native.
              export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
              export CFLAGS="''${CFLAGS:-} -I${glib.dev}/include/glib-2.0 -I${glib.dev}/lib/glib-2.0/include"
              # GLib keeps its unversioned linker-name symlinks in the dev
              # output.  The symlinks resolve to the runtime output, so linked
              # artifacts retain only the latter.
              export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"
            ''
            else ""
          }
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --buildtype=release
        '';
      }
      {
        name = "build";
        script = ''
          # Meson records its Python module invocation in build.ninja, not the
          # environment-setting launcher used during setup.
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libslirp.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-libslirp";
        library = self;
        libs = ["-lslirp"];
        extraDeps = [pkgs.glib];
        testSource = ''
          #include <libslirp.h>
          #include <stdio.h>
          int main() {
            printf("libslirp version: %s\n", slirp_version_string());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libslirp — general purpose TCP-IP emulator used by QEMU for user-mode networking";
      homepage = "https://gitlab.freedesktop.org/slirp/libslirp";
      license = "BSD-3-Clause";
    };
  }
