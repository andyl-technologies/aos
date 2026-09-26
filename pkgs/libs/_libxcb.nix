##! X protocol C-language binding with generated extension APIs.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libxau,
  libxdmcp,
  check,
  withDocs ? true,
  packageName ? "libxcb",
}: let
  version = "1.17.0";
  probeSource = ''
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <xcb/xcb.h>

    int main(int argc, char **argv) {
        char *host = NULL;
        int display = -1;
        int screen = -1;

        if (argc > 1 && strcmp(argv[1], "bad") == 0) {
            if (xcb_parse_display("not-a-display", &host, &display, &screen)) return 2;
            free(host);
            puts("libxcb rejected malformed display");
            return 0;
        }

        int parsed = xcb_parse_display("example:3.1", &host, &display, &screen);
        int valid = parsed && host != NULL && strcmp(host, "example") == 0 && display == 3 && screen == 1;
        free(host);
        if (!valid) return 3;
        puts("libxcb parsed display address");
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
      "-lxcb"
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
    pname = packageName;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An X display address with a host, display, and screen.";
        operation = "Parse the address through libxcb.";
        expected = "The parsed host, display, and screen match the input.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe"];
            exit_code = 0;
            stdout.exact = "libxcb parsed display address\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A string without X display address syntax.";
        operation = "Parse the malformed address through libxcb.";
        expected = "Libxcb rejects the malformed address.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe" "bad"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libxcb rejected malformed display\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libxcb-${version}.tar.xz"];
      hash = "0mbdkajqhg0j0zjc9a2z1qyv9mca797ihvifc9qyl3vijscvz7jr";
    };
    buildDeps =
      [buildPackages.gnumake buildPackages.pkg-config buildPackages.python3 buildPackages.xcb-proto buildPackages.libxslt]
      ++ (
        if withDocs
        then [buildPackages.doxygen buildPackages.graphviz]
        else []
      );
    runtimeDeps = [libxau libxdmcp check];
    propagatedDeps = [libxau libxdmcp];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libxcb-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            export PYTHON=${buildPackages.python3}/bin/python3
            export PKG_CONFIG_PATH="${buildPackages.xcb-proto}/lib/pkgconfig:$PKG_CONFIG_PATH"
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static ${
              if withDocs
              then "--enable-devel-docs --with-doxygen"
              else "--disable-devel-docs --without-doxygen"
            }
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
            mkdir -p "$out/share/licenses/libxcb"
            cp COPYING "$out/share/licenses/libxcb/"
          '';
        }
      ];
    meta = {
      description = "X protocol C-language binding";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
