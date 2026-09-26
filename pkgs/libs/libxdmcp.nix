##! X Display Manager Control Protocol library and specification.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
  docbook-xml-4-3,
  docbook-xsl,
}: let
  version = "1.1.5";
  probeSource = ''
    #include <stdio.h>
    #include <string.h>
    #include <X11/Xdmcp.h>

    int main(int argc, char **argv) {
        BYTE bytes[2] = {0};
        XdmcpBuffer buffer = {bytes, 2, 0, 0};
        CARD16 value = 0;

        if (argc > 1 && strcmp(argv[1], "bad") == 0) {
            buffer.count = 1;
            if (XdmcpReadCARD16(&buffer, &value)) return 2;
            puts("libxdmcp rejected truncated field");
            return 0;
        }

        if (!XdmcpWriteCARD16(&buffer, 0x1234)) return 3;
        buffer.count = buffer.pointer;
        buffer.pointer = 0;
        if (!XdmcpReadCARD16(&buffer, &value) || value != 0x1234) return 4;
        puts("libxdmcp field round trip passed");
        return 0;
    }
  '';
  compileProbe = {
    argv = [
      "@cc@"
      "-I@out@/include"
      "probe.c"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "-lXdmcp"
      "-o"
      "probe"
    ];
    exit_code = 0;
  };
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
    pname = "libxdmcp";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-byte X display manager protocol field.";
        operation = "Write and read it through libXdmcp's buffer API.";
        expected = "The decoded field equals the original value.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe"];
            exit_code = 0;
            stdout.exact = "libxdmcp field round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A truncated protocol field containing only one byte.";
        operation = "Attempt to read a two-byte field from the short buffer.";
        expected = "LibXdmcp rejects the truncated field.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe" "bad"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libxdmcp rejected truncated field\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXdmcp-${version}.tar.xz"];
      hash = "1312l8x3asib77wgf123w3nbabnky61mb6pnmmqapbf350l259fq";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.xmlto buildPackages.libxslt buildPackages.xorg-sgml-doctools];
    runtimeDeps = [xorgproto];
    propagatedDeps = [xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXdmcp-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            export XML_CATALOG_FILES="${docbook-xml-4-3}/share/xml/docbook/schema/dtd/4.3/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static --enable-docs --with-xmlto --with-xsltproc
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
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
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libxdmcp"
            cp COPYING "$out/share/licenses/libxdmcp/"
          '';
        }
      ];
    meta = {
      description = "X Display Manager Control Protocol library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
