##! BibTeX — Bibliography processor used by documentation generators.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bash,
  zlib,
}: let
  sourceVersion = "20260301";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "bibtex";
    version = "0.99e-texlive-${sourceVersion}";
    outputs = ["out" "tools"];
    src = fetchurl {
      urls = ["https://mirrors.ctan.org/systems/texlive/Source/texlive-${sourceVersion}-source.tar.xz"];
      hash = "1w70yn1gqq1jjb461rhn8l3zyfb1pbbrbpzv5xl0mf1zvmz85sij";
    };

    buildDeps =
      [buildPackages.gnumake buildPackages.perl buildPackages.flex buildPackages.bison buildPackages.pkg-config]
      ++ (
        if stdenv.isCross
        then [buildPackages.bibtex.tools]
        else []
      );
    runtimeDeps = [bash zlib];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd texlive-${sourceVersion}-source
            for directory in build-aux texk/kpathsea texk/web2c; do
              AOS_RUNTIME_SHELL="${bash}/bin/bash" AOS_BUILD_SHELL="$CONFIG_SHELL" \
                "$CONFIG_SHELL" ${../../stdenv/runtime-scripts.sh} "$directory"
            done
          '';
        }
        {
          name = "configure";
          script = ''
            # WEB source translation executes on the build platform.
            export BUILDCC="''${BUILD_CC:-$CC}"
            mkdir build
            cd build
            # Select the WEB-to-C tools and their Kpathsea dependency. This
            # package installs BibTeX, not the unrelated typesetting engines.
            $CONFIG_SHELL ../configure $configureFlags --prefix="$out" \
              --disable-all-pkgs --enable-web2c --disable-native-texlive-build \
              --with-system-zlib --disable-missing --without-x \
              --disable-tex --disable-etex --disable-uptex --disable-euptex \
              --disable-aleph --disable-hitex --disable-pdftex --disable-luatex \
              --disable-luajittex --disable-luahbtex --disable-luajithbtex \
              --disable-mp --disable-pmp --disable-texprof --disable-upmp \
              --disable-xetex --disable-mf --disable-mflua --disable-mfluajit

          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
            make -C texk/web2c -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" bibtex tangle ctangle tie otangle
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
              (
                cd texk/web2c
                srcdir="$PWD/../../../texk/web2c" \
                  "$CONFIG_SHELL" ../../../texk/web2c/bibtex.test
              )
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make -C texk/kpathsea install SHELL="$CONFIG_SHELL"
            install -D -m755 texk/web2c/bibtex "$out/bin/bibtex"
            mkdir -p "$tools/bin" "$tools/share/licenses/bibtex"
            for tool in tangle ctangle tie otangle; do
              install -m755 "texk/web2c/$tool" "$tools/bin/$tool"
            done
            install -D -m644 ../texk/web2c/man/bibtex.man "$out/share/man/man1/bibtex.1"
            mkdir -p "$out/share/licenses/bibtex"
            cp ../texk/web2c/bibtex.web "$out/share/licenses/bibtex/"
            cp ../texk/kpathsea/COPYING.LESSERv2 "$out/share/licenses/bibtex/"
            cp ../texk/web2c/pdftexdir/COPYINGv2 "$out/share/licenses/bibtex/"
            cp -R "$out/share/licenses/bibtex/." "$tools/share/licenses/bibtex/"
            AOS_RUNTIME_SHELL="${bash}/bin/bash" AOS_BUILD_SHELL="$CONFIG_SHELL" \
              "$CONFIG_SHELL" ${../../stdenv/runtime-scripts.sh} "$out"
          '';
        }
      ];

    meta = {
      description = "BibTeX bibliography processor with Kpathsea file lookup";
      homepage = "https://tug.org/bibtex/";
      license = "Knuth-CTAN AND GPL-2.0-or-later AND LGPL-2.1-or-later";
    };
  }
