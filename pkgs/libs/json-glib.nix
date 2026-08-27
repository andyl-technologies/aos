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
  buildPackages,
}: let
  version = "1.10.6";
  majorMinor = "1.10";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
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

    buildDeps =
      if isDarwinCross
      then [
        buildPackages.gnumake
        buildPackages.pkg-config
        buildPackages.meson
        buildPackages.ninja
        buildPackages.python3
        buildPackages.glib.tools
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
        script =
          if isDarwinCross
          then ''
            # Keep generator programs native while exposing the target
            # GLib headers, linker names, and pkg-config metadata.
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            export CFLAGS="''${CFLAGS:-} -I${glib.dev}/include/glib-2.0 -I${glib.dev}/lib/glib-2.0/include"
            export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"

            meson setup build \
              $mesonFlags \
              --prefix=$out \
              --buildtype=release \
              -Dintrospection=disabled \
              -Dgtk_doc=disabled \
              -Dman=false \
              -Dtests=false \
              -Dnls=disabled
          ''
          else ''
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

    meta = {
      description = "GLib-based JSON parsing and generation library";
      homepage = "https://gitlab.gnome.org/GNOME/json-glib";
      license = "LGPL-2.1-or-later";
    };
  }
