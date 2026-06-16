##! glib — GLib core library (data structures, type system, event loop)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  libffi,
  pcre2,
  zlib,
  util-linux,
}: let
  version = "2.82.4";
  majorMinor = builtins.concatStringsSep "." (
    builtins.genList (i: builtins.elemAt (builtins.split "\\." version) (i * 2)) 2
  );
in
  mkDerivation {
    pname = "glib";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/glib/${majorMinor}/glib-${version}.tar.xz"
      ];
      hash = "sha256-N90Id/6WTNFemicQsEShgw+xvZNlKm0Mtriy3/GHxwk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
      python3
    ];
    runtimeDeps = [
      libffi
      pcre2
      zlib
      util-linux
      # glib installs python tools (glib-mkenums, glib-genmarshal,
      # gdbus-codegen) used by downstream builds; their shebangs point at
      # this interpreter, so it must stay in the closure. As a build-only
      # dep it would be a runtime ref and nuke-references would rewrite the
      # shebang to a placeholder, breaking the tools (e.g. json-glib build).
      python3
    ];
    propagatedDeps = [
      libffi
      pcre2
      zlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd glib-${version}
          # Patch Python shebangs so scripts can be found in the Nix sandbox
          find . -type f -name '*.py' | while read f; do
            if head -1 "$f" | grep -q '^#!'; then
              sed -i "1s|#!/usr/bin/env python3|#!${python3}/bin/python3|" "$f"
              sed -i "1s|#!/usr/bin/python3|#!${python3}/bin/python3|" "$f"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          # GLib's meson build needs python3 in PATH for codegen scripts
          export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

          meson setup build \
            --prefix=$out \
            --buildtype=release \
            -Dselinux=disabled \
            -Dxattr=false \
            -Dlibmount=enabled \
            -Dman-pages=disabled \
            -Ddtrace=disabled \
            -Dsystemtap=disabled \
            -Ddocumentation=false \
            -Dinstalled_tests=false \
            -Dnls=disabled \
            -Doss_fuzz=disabled \
            -Dglib_checks=true \
            -Dglib_assert=false \
            -Dtests=false
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

    meta = {
      description = "glib — GLib core library providing data structures, type system, and event loop";
      homepage = "https://wiki.gnome.org/Projects/GLib";
      license = "LGPL-2.1-or-later";
    };
  }
