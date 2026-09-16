##! libmetalink — Metalink XML document parser
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  file,
  expat,
}: let
  version = "0.1.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libmetalink";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser returns one Metalink 4 file with the declared name and size.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmetalink primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmetalink rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <metalink/metalink.h>\nint main(void) {\n    const char *document = \"<metalink xmlns='urn:ietf:params:xml:ns:metalink'><file name='answer.txt'><size>42</size></file></metalink>\";\n    metalink_t *metalink = NULL;\n    int status = metalink_parse_memory(document, strlen(document), &metalink);\n    int valid = status == 0 && metalink != NULL && metalink->version == METALINK_VERSION_4\n        && metalink->files != NULL && metalink->files[0] != NULL\n        && strcmp(metalink->files[0]->name, \"answer.txt\") == 0\n        && metalink->files[0]->size == 42;\n    metalink_delete(metalink);\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "A Metalink 4 document describing answer.txt with a size of 42 bytes.";
        "operation" = "Parse the in-memory XML document through metalink_parse_memory.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmetalink"
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
              "exact" = "libmetalink primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The Metalink parser returns a nonzero syntax error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmetalink primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmetalink rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <metalink/metalink.h>\nint main(void) {\n    const char *document = \"not XML\";\n    metalink_t *metalink = NULL;\n    int status = metalink_parse_memory(document, strlen(document), &metalink);\n    if (status == 0) {\n        metalink_delete(metalink);\n        return 2;\n    }\n    return reject();\n}\n\n";
        };
        "input" = "Plain text that is not an XML document.";
        "operation" = "Parse the malformed document through metalink_parse_memory.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmetalink"
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
              "exact" = "libmetalink rejected invalid input\n";
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
        "https://github.com/metalink-dev/libmetalink/releases/download/release-${version}/libmetalink-${version}.tar.bz2"
      ];
      hash = "sha256-B1OuEVLZcNw78yfQzlz+/sovGrEylLEV5kgRFjpo/U8=";
    };

    buildDeps = [gnumake pkg-config file];
    runtimeDeps = [expat];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libmetalink-${version}
          sed -i "s|/usr/bin/file|${file}/bin/file|g" configure
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --disable-static \
            --without-libxml2 \
            --with-libexpat
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make -j"$NIX_BUILD_CORES" check'';
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
        pname = "lib-libmetalink";
        library = self;
        libs = ["-lmetalink"];
        testSource = ''
          #include <metalink/metalink.h>

          int main(void) {
              metalink_t *document = NULL;
              metalink_delete(document);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "C library for parsing Metalink XML documents";
      homepage = "https://github.com/metalink-dev/libmetalink";
      license = "MIT";
    };
  }
