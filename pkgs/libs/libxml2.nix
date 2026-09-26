##! libxml2 — XML parsing library (GNOME)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  bash,
  stdenv,
}: let
  version = "2.15.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libxml2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The root element is named answer.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libxml2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libxml2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libxml/parser.h>\n#include <libxml/tree.h>\nint main(void) {\n    const char document[] = \"<answer>42</answer>\";\n    xmlDocPtr parsed = xmlReadMemory(document, sizeof(document) - 1, \"input.xml\", NULL, XML_PARSE_NONET);\n    if (parsed == NULL) return 2;\n    xmlNodePtr root = xmlDocGetRootElement(parsed);\n    int ok = root != NULL && xmlStrEqual(root->name, BAD_CAST \"answer\");\n    xmlFreeDoc(parsed);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "An XML document with a root element and text child.";
        "operation" = "Parse the document and inspect its root through libxml2.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libxml2"
              "-lxml2"
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
              "exact" = "libxml2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libxml2 rejects the document and returns no parsed tree.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libxml2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libxml2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libxml/parser.h>\nint main(void) {\n    const char document[] = \"<open></closed>\";\n    xmlDocPtr parsed = xmlReadMemory(document, sizeof(document) - 1, \"bad.xml\", NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);\n    if (parsed != NULL) { xmlFreeDoc(parsed); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "An XML document with mismatched element tags.";
        "operation" = "Parse the malformed document with network access disabled.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libxml2"
              "-lxml2"
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
              "exact" = "libxml2 rejected invalid input\n";
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
        "https://download.gnome.org/sources/libxml2/${builtins.concatStringsSep "." (builtins.genList (i: builtins.elemAt (builtins.splitVersion version) i) 2)}/libxml2-${version}.tar.xz"
      ];
      hash = "sha256-mAh/0YHZBwck8/vGXHN32wMDjrkr2II3Ta/0SUATiCE=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libxml2-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --enable-shared \
              --with-zlib=${zlib} \
              --without-python \
              --without-icu \
              --without-lzma \
              --without-readline \
              --without-history
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
          script =
            if stdenv.hostPlatform.isDarwin
            then ''
              make install
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/xml2-config"
            ''
            else ''
              make install
            '';
        }
      ];

    meta = {
      description = "libxml2 — XML C parser and toolkit";
      homepage = "https://gitlab.gnome.org/GNOME/libxml2";
      license = "MIT";
    };
  }
