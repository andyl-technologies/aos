##! gsettings-desktop-schemas — Shared desktop settings schemas
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  gettext,
  glib,
  buildPackages,
}: let
  version = "50.1";
in
  mkDerivation {
    pname = "gsettings-desktop-schemas";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/gsettings-desktop-schemas/50/gsettings-desktop-schemas-${version}.tar.xz"
      ];
      hash = "sha256-CiqiUIJnJYXRb82rYcew4z8DX7h0dlBceU8pVlr6SFs=";
    };

    buildDeps = [meson ninja pkg-config gettext glib.tools];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gsettings-desktop-schemas-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Dintrospection=false
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
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
          ${glib.tools}/bin/glib-compile-schemas "$out/share/glib-2.0/schemas"
        '';
      }
    ];

    meta = {
      description = "GSettings schemas shared by desktop components";
      homepage = "https://gitlab.gnome.org/GNOME/gsettings-desktop-schemas";
      license = "LGPL-2.1-or-later";
    };
  }
