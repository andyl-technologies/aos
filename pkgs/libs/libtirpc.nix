##! libtirpc — Transport Independent RPC library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  stdenv,
}: let
  version = "1.3.7";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libtirpc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The decoded integer equals the original value.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtirpc primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtirpc rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdint.h>\n#include <rpc/xdr.h>\nint main(void) {\n    char buffer[16] = {0}; uint32_t input = 42, output = 0; XDR stream;\n    xdrmem_create(&stream, buffer, sizeof(buffer), XDR_ENCODE);\n    if (!xdr_u_int32_t(&stream, &input)) return 2;\n    unsigned int used = xdr_getpos(&stream); xdr_destroy(&stream);\n    xdrmem_create(&stream, buffer, used, XDR_DECODE);\n    int ok = xdr_u_int32_t(&stream, &output) && output == input; xdr_destroy(&stream);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "The unsigned integer 42 encoded into an in-memory XDR stream.";
        "operation" = "Encode and decode the value through xdrmem_create and xdr_u_int32_t.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/tirpc"
              "-ltirpc"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libtirpc primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libtirpc reports decoding failure.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtirpc primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtirpc rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdint.h>\n#include <rpc/xdr.h>\nint main(void) {\n    char buffer[3] = {0}; uint32_t output = 0; XDR stream;\n    xdrmem_create(&stream, buffer, sizeof(buffer), XDR_DECODE);\n    int accepted = xdr_u_int32_t(&stream, &output); xdr_destroy(&stream);\n    if (accepted) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An XDR buffer shorter than one encoded 32-bit integer.";
        "operation" = "Decode the truncated stream through xdr_u_int32_t.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/tirpc"
              "-ltirpc"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libtirpc rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/libtirpc/files/libtirpc/${version}/libtirpc-${version}.tar.bz2"
      ];
      hash = "sha256-tH06wZ01SeVKBdABmmxABnTacWEjhYz9ttO91wpmxwI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtirpc-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            CPPFLAGS="-D__APPLE_USE_RFC_3542" ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-gssapi
            sed -i 's/-Wl,--no-undefined//g' src/Makefile
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-gssapi
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "libtirpc — Transport Independent RPC library";
      homepage = "https://sourceforge.net/projects/libtirpc/";
      license = "BSD-3-Clause";
    };
  }
