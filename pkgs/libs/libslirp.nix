##! libslirp — General purpose TCP-IP emulator (user-mode networking for QEMU)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  glib,
}: let
  version = "4.9.1";
in
  mkDerivation {
    pname = "libslirp";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gitlab.freedesktop.org/slirp/libslirp/-/archive/v${version}/libslirp-v${version}.tar.gz"
      ];
      hash = "sha256-OXBUIUO3wR5qCaTStQ8woTNHPEHxXtC9zDt6HEUNmlw=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
      python3
      glib.dev
      glib.tools
    ];
    runtimeDeps = [
      glib
    ];
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
          export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          meson setup build \
            --prefix=$out \
            --buildtype=release
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
