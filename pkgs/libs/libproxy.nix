##! libproxy — Automatic proxy configuration library
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  glib,
  util-linux,
  zlib,
  curl,
  duktape,
  gsettings-desktop-schemas,
  buildPackages,
}: let
  version = "0.5.12";
in
  mkDerivation {
    pname = "libproxy";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libproxy/libproxy/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-ofpVmRmYuApWdFCp6EOCQhpxdqhERslcqqi3LPCfqG8=";
    };

    buildDeps = [meson ninja pkg-config glib.dev glib.tools];
    runtimeDeps = [
      glib
      util-linux
      zlib
      curl
      duktape
      gsettings-desktop-schemas
    ];
    propagatedDeps = [glib curl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libproxy-${version}

          # Meson receives release sources without Git metadata, so the hook
          # installer is intentionally inert but must remain executable.
          chmod +x data/install-git-hook.sh

          # Public libproxy headers expose GObject types. Advertise that
          # requirement to dynamic consumers as well as static consumers.
          sed -i \
            "s/requires_private: 'gobject-2.0'/requires: 'gobject-2.0'/" \
            src/libproxy/meson.build
        '';
      }
      {
        name = "configure";
        script = ''
          export PKG_CONFIG_PATH="${gsettings-desktop-schemas}/share/pkgconfig:$PKG_CONFIG_PATH"
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Drelease=true \
            -Ddocs=false \
            -Dintrospection=false \
            -Dvapi=false
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          GSETTINGS_SCHEMA_DIR=${gsettings-desktop-schemas}/share/glib-2.0/schemas \
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson test -C build --print-errorlogs
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
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libproxy";
        library = self;
        libs = ["-lproxy"];
        testSource = ''
          #include <proxy.h>

          int main(void) {
              px_proxy_factory *factory = px_proxy_factory_new();
              if (factory == NULL) {
                  return 1;
              }
              px_proxy_factory_free(factory);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-libproxy";
        tool = self;
        command = "proxy --help >/dev/null";
      };
    };

    meta = {
      description = "Automatic proxy configuration management library";
      homepage = "https://libproxy.github.io/libproxy/";
      license = "LGPL-2.1-or-later";
      mainProgram = "proxy";
    };
  }
