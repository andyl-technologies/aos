##! Vala compiler, binding generator, and API documentation tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  callPackage,
  stdenv,
  graphviz,
  util-linux,
}: let
  version = "0.56.19";
  glib = callPackage ../libs/_image-glib.nix {};
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "vala";
    inherit version;
    src = fetchurl {
      urls = ["https://download.gnome.org/sources/vala/0.56/vala-${version}.tar.xz"];
      hash = "1mdrvxx0j2sv7g1swqp1v3mznns5c3pwk5v77m01prhdrjzwpmss";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.gobject-introspection buildPackages.dbus buildPackages.flex buildPackages.bison];
    runtimeDeps =
      [glib graphviz]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux]
        else []
      );
    propagatedDeps =
      [glib]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd vala-${version}
            # The release's generated C sources bootstrap valac without a binary seed.
            find build-aux -type f -name '*.sh' -exec \
              sed -i '1s|^#!.*sh.*$|#!${buildPackages.bash}/bin/bash|' {} +
            # Keep declared dependencies visible when tests add uninstalled Vala metadata.
            sed -i '/^export PKG_CONFIG_PATH=/s|$|:$PKG_CONFIG_PATH|' \
              valadoc/tests/libvaladoc/tests-extra-environment.sh
          '';
        }
        {
          name = "configure";
          script = ''
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            # GIR test compilation resolves GLib's installed introspection data.
            export XDG_DATA_DIRS="${glib}/share:${buildPackages.gobject-introspection}/share"
            export GI_GIRDIR="${glib}/share/gir-1.0"
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" \
              --enable-valadoc --with-cgraph
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
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
              if ! make check -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"; then
                find . -name test-suite.log -exec cat {} +
                exit 1
              fi
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install SHELL="$CONFIG_SHELL"
            # This executable lives below lib rather than bin, so the generic
            # executable fixup misses its compiler-header debug references.
            "$STRIP" --strip-debug "$out/lib/vala-0.56/gen-introspect-0.56"
            mkdir -p "$out/share/licenses/vala"
            cp COPYING* "$out/share/licenses/vala/"
          '';
        }
      ];

    meta = {
      description = "Vala compiler, binding generator, and API documentation tools";
      homepage = "https://vala.dev/";
      license = "LGPL-2.1-or-later";
    };
  }
