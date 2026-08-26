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
  stdenv,
  buildPackages,
}: let
  version = "4.9.1";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
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

    buildDeps =
      if isDarwinCross
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
            if isDarwinCross
            then ''
              # Meson's sys_root property is correct for ordinary FHS cross
              # sysroots, but pkg-config must not prepend the Darwin SDK to
              # absolute Nix store paths from GLib's .pc files.  Keep the
              # generated dependency metadata and provide its absolute target
              # include/library roots explicitly.
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
