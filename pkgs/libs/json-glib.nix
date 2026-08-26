{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  glib,
  util-linux,
  zlib,
  stdenv,
}: let
  version = "1.10.6";
  majorMinor = "1.10";
in
  mkDerivation {
    pname = "json-glib";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/json-glib/${majorMinor}/json-glib-${version}.tar.xz"
      ];
      hash = "sha256-d/S8v5M5Uo8Wa4BzRYaT8KILd7cFnbwtthdGoZKLApM=";
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
    # glib's gio-2.0.pc has `Requires.private: zlib, mount` (libmount, from
    # util-linux); pkg-config 0.29 resolves private deps too, so those must
    # be reachable or `dependency('gio-2.0')` fails. glib lists util-linux
    # only in runtimeDeps (not propagated), so name them here directly.
    runtimeDeps =
      [glib zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );
    propagatedDeps =
      [glib zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd json-glib-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --buildtype=release \
            -Dintrospection=disabled \
            -Dgtk_doc=disabled \
            -Dman=false \
            -Dtests=false \
            -Dnls=disabled
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
      description = "GLib-based JSON parsing and generation library";
      homepage = "https://gitlab.gnome.org/GNOME/json-glib";
      license = "LGPL-2.1-or-later";
    };
  }
