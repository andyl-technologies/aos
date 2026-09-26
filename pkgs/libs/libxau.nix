##! X11 authorization-file library and manual pages.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
}: let
  version = "1.0.12";
  probeSource = ''
    #include <stdio.h>
    #include <string.h>
    #include <X11/Xauth.h>

    int main(int argc, char **argv) {
        FILE *file = tmpfile();
        if (file == NULL) return 2;

        if (argc > 1 && strcmp(argv[1], "bad") == 0) {
            fputs("invalid", file);
            rewind(file);
            Xauth *parsed = XauReadAuth(file);
            fclose(file);
            if (parsed != NULL) {
                XauDisposeAuth(parsed);
                return 3;
            }
            puts("libxau rejected truncated record");
            return 0;
        }

        Xauth source = {FamilyLocal, 4, "host", 1, "0", 18, "MIT-MAGIC-COOKIE-1", 4, "AOS!"};
        if (!XauWriteAuth(file, &source)) return 4;
        rewind(file);
        Xauth *parsed = XauReadAuth(file);
        fclose(file);
        if (parsed == NULL) return 5;
        int valid = parsed->family == FamilyLocal && parsed->data_length == 4 && memcmp(parsed->data, "AOS!", 4) == 0;
        XauDisposeAuth(parsed);
        if (!valid) return 6;
        puts("libxau round trip passed");
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
      "-lXau"
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
    pname = "libxau";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An X authorization record with a four-byte cookie.";
        operation = "Write and read the record through libXau.";
        expected = "The round trip preserves the address family and cookie.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe"];
            exit_code = 0;
            stdout.exact = "libxau round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A truncated X authorization record.";
        operation = "Attempt to read it through libXau.";
        expected = "The library rejects it without returning an authorization record.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe" "bad"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libxau rejected truncated record\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXau-${version}.tar.xz"];
      hash = "1yy0gx3psxyjcj284xhh44labav7b5zs7gcrks9xi6nklggy9l3l";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto];
    propagatedDeps = [xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXau-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static
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
            mkdir -p "$out/share/licenses/libxau"
            cp COPYING "$out/share/licenses/libxau/"
          '';
        }
      ];
    meta = {
      description = "X11 authorization-file library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
