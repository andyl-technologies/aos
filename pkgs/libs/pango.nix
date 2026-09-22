##! pango — Text layout and rendering for image processing.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  callPackage,
  gobject-introspection,
  freetype,
  cairo,
  harfbuzz,
  fribidi,
  fontconfig,
  util-linux,
}: let
  glib = callPackage ./_image-glib.nix {};
  version = "1.58.2";
  src = fetchurl {
    urls = ["https://download.gnome.org/sources/pango/1.58/pango-${version}.tar.xz"];
    hash = "0jip3r1cwkgdsrdlrgf31gh8ji5yglxs303wbm2p6z1vrav8a8rl";
  };
  fallbackFontFixture = fetchurl {
    name = "NotoSans.ttf";
    urls = ["https://raw.githubusercontent.com/google/fonts/2984c575fdce412ee02b2baaba67672b9a9434d8/ofl/notosans/NotoSans%5Bwdth,wght%5D.ttf"];
    hash = "0gbbx1pr1kzgas7gmqyp68j9317p0cxc0in39mrjxw8k2mlvpdxz";
  };
  fallbackFontLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/google/fonts/2984c575fdce412ee02b2baaba67672b9a9434d8/ofl/notosans/OFL.txt"];
    hash = "06h6bk1b3cp2085zgskwxs31sql9dbp3g5cy5j4gxj0ckwpqksff";
  };
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "pango";
    inherit version src;
    passthru.evidenceSources = [src fallbackFontFixture fallbackFontLicense];

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.gobject-introspection buildPackages.gtk-doc];
    runtimeDeps =
      [glib freetype cairo harfbuzz fribidi fontconfig]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux]
        else []
      );
    # Installed pkg-config files expose both public and private dependencies.
    propagatedDeps =
      [glib freetype cairo harfbuzz fribidi fontconfig]
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
            cd pango-${version}
            # Meson executes source generators directly during configuration.
            find . -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
            # Use the shipped font fixtures instead of the machine's fonts.
            cp tests/fonts/fonts.conf tests/hermetic-fonts.conf
            mkdir tests/fallback-fonts
            cp ${fallbackFontFixture} tests/fallback-fonts/NotoSans.ttf
            sed -i "/<fontconfig>/a\\  <dir>$PWD/tests/fonts</dir>" tests/hermetic-fonts.conf
            sed -i "/<fontconfig>/a\\  <dir>$PWD/tests/fallback-fonts</dir>" tests/hermetic-fonts.conf
            # Boxes intentionally lacks lowercase letters and digits. Pin its
            # fallback to the declared Noto Sans fixture for metric assertions.
            sed -i '/<fontconfig>/a\  <match><test name="family"><string>Boxes</string></test><edit name="family" mode="append"><string>Noto Sans</string></edit></match>' \
              tests/hermetic-fonts.conf
            sed -i "s|'/etc/fonts/fonts.conf'|meson.current_source_dir() / 'hermetic-fonts.conf'|" tests/meson.build
          '';
        }
        {
          name = "configure";
          script = ''
            # Native scanner dependencies also expose bootstrap GLib metadata.
            # Resolve the target image stack's GLib first.
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export XDG_DATA_DIRS="${glib}/share:${harfbuzz}/share:${buildPackages.gobject-introspection}/share"
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
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dintrospection=enabled
          '';
        }
        {
          name = "build";
          script = ''
            # Ninja invokes Meson's Python helpers without its CLI wrapper.
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
              mkdir -p locales
              I18NPATH="${buildPackages.glibc.bin}/share/i18n" \
                ${buildPackages.glibc.bin}/bin/localedef --no-archive \
                  --inputfile=en_US --charmap=UTF-8 "$PWD/locales/en_US.UTF-8"
              export LOCPATH="$PWD/locales"
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
            mkdir -p "$out/share/licenses/pango"
            cp COPYING "$out/share/licenses/pango/"
          '';
        }
      ];

    meta = {
      description = "Text layout and rendering library with Cairo and font configuration support";
      homepage = "https://pango.gnome.org/";
      license = "LGPL-2.1-or-later";
    };
  }
