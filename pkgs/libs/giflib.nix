##! giflib — GIF decoding, encoding, and format utilities.
{
  mkDerivation,
  callPackage,
  buildPackages,
  stdenv,
}: let
  version = "6.1.3-unstable-a8e3114";
  src = callPackage ./_giflib-source.nix {};
  platformName =
    if stdenv.hostPlatform.isDarwin
    then "Darwin"
    else "Linux";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "giflib";
    inherit version src;
    buildDeps = [buildPackages.gnumake buildPackages.libxslt buildPackages.docbook-xml buildPackages.docbook-xsl];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
            sed -i '1c#!${buildPackages.bash}/bin/bash' getversion

            # Apply the same DocBook stylesheets directly with AOS xsltproc.
            # Both HTML and manual-page targets remain part of the normal build.
            sed -i \
              -e 's|xmlto xhtml-nochunks $<|xsltproc --nonet -o $@ ${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/docbook-xsl/xhtml/docbook.xsl $<|' \
              -e 's|xmlto man $<|xsltproc --nonet ${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl $<|' \
              doc/Makefile
            export XML_CATALOG_FILES="${buildPackages.docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" \
              CC="$CC" AR="$AR" UNAME=${platformName} PREFIX="$out"
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
              # Canonical disassembly checks the image data across decode/encode.
              ./gifbuild -d < pic/gifgrid.gif > original.txt
              ./gifbuild < original.txt > roundtrip.gif
              ./gifbuild -d < roundtrip.gif > roundtrip.txt
              cmp original.txt roundtrip.txt
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install SHELL="$CONFIG_SHELL" CC="$CC" AR="$AR" \
              UNAME=${platformName} PREFIX="$out"
            mkdir -p "$out/share/licenses/giflib"
            cp COPYING "$out/share/licenses/giflib/"
          '';
        }
      ];

    meta = {
      description = "GIF image library, utilities, and documentation";
      homepage = "https://giflib.sourceforge.net/";
      license = "MIT";
    };
  }
