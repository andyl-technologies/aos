##! fstrm — Frame Streams implementation in C
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  m4,
  pkg-config,
  libevent,
  openssl,
}: let
  version = "0.6.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "fstrm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API accepts the bounded value and clears the destroyed handle.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <fstrm.h>\n\nint main(void) {\n    const char content_type[] = \"application/aos-qualification\";\n    struct fstrm_writer_options *options = fstrm_writer_options_init();\n    if (options == NULL) {\n        return 2;\n    }\n    if (fstrm_writer_options_add_content_type(\n            options, content_type, strlen(content_type)) != fstrm_res_success) {\n        fstrm_writer_options_destroy(&options);\n        return 3;\n    }\n    fstrm_writer_options_destroy(&options);\n    if (options != NULL) {\n        return 4;\n    }\n    return puts(\"fstrm api passed\") == EOF;\n}\n";
        };
        "input" = "A writer-options object and a short Frame Streams content type.";
        "operation" = "Create the options, add the content type, and destroy the object.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfstrm"
              "-o"
              "primary"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "fstrm api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API returns failure and does not accept the content type.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <string.h>\n#include <fstrm.h>\n\nint main(void) {\n    unsigned char content_type[FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX + 1];\n    memset(content_type, 'x', sizeof(content_type));\n    struct fstrm_writer_options *options = fstrm_writer_options_init();\n    if (options == NULL) {\n        return 2;\n    }\n    fstrm_res result = fstrm_writer_options_add_content_type(\n        options, content_type, sizeof(content_type));\n    fstrm_writer_options_destroy(&options);\n    if (result != fstrm_res_failure) {\n        return 3;\n    }\n    fputs(\"fstrm rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A content type one byte longer than Frame Streams permits.";
        "operation" = "Add the oversized value to a writer-options object.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfstrm"
              "-o"
              "bad-input"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "fstrm rejected invalid input\n";
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
        "https://github.com/farsightsec/fstrm/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-Tw960rdgEZxEGrpYJx6E3mg7PME4Uw0CcQiWZBhm4tI=";
    };

    buildDeps = [gnumake autoconf automake libtool m4 pkg-config];
    runtimeDeps = [libevent openssl];
    propagatedDeps = [libevent];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd fstrm-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal:${pkg-config}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          autoreconf -fi
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-fstrm";
        library = self;
        libs = ["-lfstrm"];
        testSource = ''
          #include <fstrm.h>

          int main(void) {
              struct fstrm_writer_options *options = fstrm_writer_options_init();
              if (options == NULL) return 1;
              fstrm_writer_options_destroy(&options);
              return options == NULL ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Frame Streams implementation in C";
      homepage = "https://github.com/farsightsec/fstrm";
      license = "Apache-2.0";
    };
  }
