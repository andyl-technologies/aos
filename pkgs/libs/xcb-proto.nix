##! XCB protocol descriptions and Python code-generation modules.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.17.0";
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
    pname = "xcb-proto";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed core XCB protocol description.";
        operation = "Register and resolve the protocol with its installed xcbgen module.";
        expected = "XCB's CreateWindow request resolves in the core protocol.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import __main__

                callbacks = ("open", "close", "enum", "error", "event", "eventstruct", "request", "simple", "struct", "union")
                __main__.output = {name: (lambda *args: None) for name in callbacks}

                from xcbgen.state import Module

                module = Module("@out@/share/xcb/xproto.xml", "probe")
                module.register()
                module.resolve()
                assert ("xcb", "CreateWindow") in [name for name, _ in module.all]
                print("xcb protocol resolved CreateWindow")
              ''
            ];
            exit_code = 0;
            stdout.exact = "xcb protocol resolved CreateWindow\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A protocol description with mismatched XML tags.";
        operation = "Parse the malformed description through xcbgen.";
        expected = "Xcbgen rejects the malformed protocol XML.";
        files."broken.xml" = "<xcb><request></xcb>\n";
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import __main__
                from xml.etree.ElementTree import ParseError

                callbacks = ("open", "close", "enum", "error", "event", "eventstruct", "request", "simple", "struct", "union")
                __main__.output = {name: (lambda *args: None) for name in callbacks}

                from xcbgen.state import Module

                try:
                    Module("broken.xml", "probe")
                except ParseError:
                    print("xcb protocol rejected malformed XML")
                else:
                    raise SystemExit(1)
              ''
            ];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "xcb protocol rejected malformed XML\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/proto/xcb-proto-${version}.tar.xz"];
      hash = "130lc8jx43s83496nc8jn47zixjcp4abgsz69pvrjiqg279aq6rc";
    };
    buildDeps = [buildPackages.gnumake buildPackages.python3 buildPackages.libxml2];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xcb-proto-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          PYTHON=${buildPackages.python3}/bin/python3 $CONFIG_SHELL ./configure --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
          mkdir -p "$out/share/licenses/xcb-proto"
          mkdir -p "$out/lib/pkgconfig"
          ln -s "$out/share/pkgconfig/xcb-proto.pc" "$out/lib/pkgconfig/xcb-proto.pc"
          cp -r doc "$out/share/doc"
          cp COPYING "$out/share/licenses/xcb-proto/"
        '';
      }
    ];
    meta = {
      description = "XCB protocol descriptions and Python generator";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
