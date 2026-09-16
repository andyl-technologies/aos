##! libproxy — Automatic proxy configuration library
{
  lib,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libproxy";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The configured proxy endpoint is returned exactly.";
        "files" = {};
        "input" = "An HTTP URL and an explicit environment proxy endpoint.";
        "operation" = "Resolve the URL through the environment configuration backend.";
        "steps" = [
          {
            "argv" = [
              "@bash@"
              "-c"
              "unset no_proxy NO_PROXY PX_DEBUG G_MESSAGES_DEBUG\n# Resolve with the package's GIO modules, independent of the desktop session.\nunset GIO_EXTRA_MODULES GIO_MODULE_DIR\nexport PX_FORCE_CONFIG=config-env\nexport http_proxy=\"$1\"\nexec \"$2/bin/proxy\" http://qualification.example/resource\n"
              "libproxy-qualification"
              "http://127.0.0.1:3128"
              "@out@"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "http://127.0.0.1:3128\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The invalid proxy is discarded and the documented direct connection fallback is returned.";
        "files" = {};
        "input" = "A proxy URI with an unterminated bracketed host.";
        "operation" = "Resolve the same URL with the malformed proxy configuration.";
        "steps" = [
          {
            "argv" = [
              "@bash@"
              "-c"
              "unset no_proxy NO_PROXY PX_DEBUG G_MESSAGES_DEBUG\n# Resolve with the package's GIO modules, independent of the desktop session.\nunset GIO_EXTRA_MODULES GIO_MODULE_DIR\nexport PX_FORCE_CONFIG=config-env\nexport http_proxy=\"$1\"\nexec \"$2/bin/proxy\" http://qualification.example/resource\n"
              "libproxy-qualification"
              "http://[broken"
              "@out@"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "direct://\n";
            };
          }
        ];
      };
    };

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
