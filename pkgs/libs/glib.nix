##! glib — GLib core library (data structures, type system, event loop)
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  meson,
  ninja,
  python3,
  libffi,
  pcre2,
  zlib,
  util-linux,
}:

let
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
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  buildDeps = [
    make
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
          -Ddtrace=false \
          -Dsystemtap=false \
          -Dgtk_doc=false \
          -Dfam=false \
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
