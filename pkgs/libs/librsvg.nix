##! SVG rendering library, conversion utility, and language bindings.
{
  mkDerivation,
  callPackage,
  buildPackages,
  stdenv,
  lib,
  gobject-introspection,
  rust,
  cairo,
  dav1d,
  freetype,
  gdk-pixbuf,
  harfbuzz,
  libxml2,
  pango,
  util-linux,
  shared-mime-info,
  glycin-image-rs,
}: let
  sources = callPackage ./_librsvg-sources.nix {};
  glib = callPackage ./_image-glib.nix {};
  buildCargoPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
  rustTool =
    if stdenv.isCross
    then rust.passthru.buildTool
    else buildPackages.rust;
  glycinDataDirPrefix =
    if stdenv.hostPlatform.isLinux
    then "${glycin-image-rs}/share:"
    else "";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "librsvg";
    inherit (sources) version src;
    passthru.evidenceSources = [sources.src sources.cargoDeps];

    buildDeps = [
      buildPackages.meson
      buildPackages.ninja
      buildPackages.python3
      buildPackages.pkg-config
      buildPackages.cargo-c
      rustTool
      buildPackages.gobject-introspection
      buildPackages.vala
      buildPackages.gi-docgen
      buildPackages.docutils
    ];
    runtimeDeps =
      [glib cairo dav1d freetype gdk-pixbuf harfbuzz libxml2 pango]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux]
        else []
      );
    # GLib's split development output owns the gobject/gio pkg-config files.
    propagatedDeps =
      [glib glib.dev cairo gdk-pixbuf dav1d freetype harfbuzz libxml2 pango]
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
            cd librsvg-${sources.version}
            mkdir -p .cargo
            sed 's|@vendor@|${sources.cargoDeps}|g' ${sources.cargoDeps}/.cargo/config.toml > .cargo/config.toml
            find meson -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_NET_OFFLINE=true
            export CARGO_BUILD_JOBS="$NIX_BUILD_CORES"
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            export RUSTFLAGS="-C linker=$CC -L native=${glib.dev}/lib"
            export XDG_DATA_DIRS="${glycinDataDirPrefix}${shared-mime-info}/share:${glib}/share:${gdk-pixbuf}/share:${buildPackages.gobject-introspection}/share:${buildPackages.vala}/share"
            ${
              if stdenv.isCross
              then ''
                # Build scripts and proc macros are native executables. Clear
                # target search paths before invoking the native C linker.
                mkdir -p native-tools
                cat > native-tools/cc <<'EOF'
                #!${buildPackages.bash}/bin/bash
                unset AOS_CROSS_COMPILING AOS_GOARCH AOS_GOOS
                unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
                unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_TARGET_ARCH AOS_TARGET_PLATFORM
                unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
                unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
                exec ${buildPackages.cc}/bin/cc "$@"
                EOF
                chmod +x native-tools/cc
                export CARGO_TARGET_${buildCargoPrefix}_LINKER="$PWD/native-tools/cc"
                export PKG_CONFIG_ALLOW_CROSS=1
                # VAPI generation executes vapigen on the builder; it does not
                # link a target library or require a target-hosted generator.
                sed -i "s/dependency('vapigen',/dependency('vapigen', native: true,/" meson.build
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
              -Dintrospection=enabled -Dpixbuf=enabled -Ddocs=enabled -Dvala=enabled \
              -Davif=enabled -Drsvg-convert=enabled -Dtests=true \
              ${
              if stdenv.isCross
              then "-Dtriplet=${stdenv.hostPlatform.config}"
              else ""
            }
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
            mkdir -p "$out/share/licenses/librsvg"
            cp COPYING* "$out/share/licenses/librsvg/"
            test -s "$out/share/gir-1.0/Rsvg-2.0.gir"
            test -s "$out/lib/girepository-1.0/Rsvg-2.0.typelib"
            test -s "$out/share/vala/vapi/librsvg-2.0.vapi"
            test -s "$out/share/doc/Rsvg-2.0/index.html"
            test -s "$out/share/man/man1/rsvg-convert.1"
          '';
        }
      ];

    meta = {
      description = "SVG rendering library and command-line conversion utility";
      homepage = "https://gitlab.gnome.org/GNOME/librsvg";
      license = "LGPL-2.1-or-later";
      mainProgram = "rsvg-convert";
    };
  }
