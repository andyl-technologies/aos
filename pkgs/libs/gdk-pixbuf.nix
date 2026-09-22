##! GDK-Pixbuf image loading, transformation, and thumbnail generation.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  gobject-introspection,
  callPackage,
  libpng,
  mozjpeg,
  libtiff,
  shared-mime-info,
  util-linux,
  libglycin,
  glycin-image-rs,
}: let
  version = "2.44.8";
  glib = callPackage ./_image-glib.nix {};
in
  mkDerivation {
    pname = "gdk-pixbuf";
    inherit version;
    src = fetchurl {
      urls = ["https://download.gnome.org/sources/gdk-pixbuf/2.44/gdk-pixbuf-${version}.tar.xz"];
      hash = "0g5saar4zk8kcl6336kzkr336fcclikb9d6l3kl146ln2aam57wi";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.gobject-introspection buildPackages.docutils buildPackages.glib.tools];
    runtimeDeps =
      [glib libpng mozjpeg libtiff shared-mime-info]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux libglycin glycin-image-rs]
        else []
      );
    # Expose the complete Requires and Requires.private pkg-config contract.
    propagatedDeps =
      [glib libpng mozjpeg libtiff shared-mime-info]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [libglycin]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd gdk-pixbuf-${version}
            # Bind executable generators without changing the image test fixtures.
            find build-aux -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:${shared-mime-info}/share/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            export XDG_DATA_DIRS="${glycin-image-rs}/share:${shared-mime-info}/share:${glib}/share:${buildPackages.gobject-introspection}/share"
            ${
              if stdenv.isCross
              then ''
                # Use native scanner programs while describing target GI libraries.
                mkdir -p .aos-introspection
                cat > .aos-introspection/ldd-target <<'EOF'
                #!${buildPackages.bash}/bin/bash
                exec ${stdenv.glibc}/lib/${stdenv.hostPlatform.dynamicLinker} --list "$@"
                EOF
                cat > .aos-introspection/g-ir-scanner <<EOF
                #!${buildPackages.bash}/bin/bash
                exec ${buildPackages.gobject-introspection}/bin/g-ir-scanner --use-ldd-wrapper="$PWD/.aos-introspection/ldd-target" "\$@"
                EOF
                chmod +x .aos-introspection/ldd-target .aos-introspection/g-ir-scanner
                cp ${gobject-introspection}/lib/pkgconfig/gobject-introspection-1.0.pc .aos-introspection/
                sed -i \
                  -e "s|^g_ir_scanner=.*|g_ir_scanner=$PWD/.aos-introspection/g-ir-scanner|" \
                  -e 's|^g_ir_compiler=.*|g_ir_compiler=${buildPackages.gobject-introspection}/bin/g-ir-compiler|' \
                  .aos-introspection/gobject-introspection-1.0.pc
                export PKG_CONFIG_PATH="$PWD/.aos-introspection:$PKG_CONFIG_PATH"
              ''
              else ""
            }
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Dpng=enabled -Djpeg=enabled -Dtiff=enabled -Dgif=enabled -Dintrospection=enabled
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/gdk-pixbuf"
            cp COPYING "$out/share/licenses/gdk-pixbuf/"
          '';
        }
      ];

    meta = {
      description = "Image loading, transformation, and thumbnail library";
      homepage = "https://gitlab.gnome.org/GNOME/gdk-pixbuf";
      license = "LGPL-2.1-or-later";
    };
  }
