##! lowdown — Simple Markdown translator
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "3.1.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "lowdown";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lowdown emits the exact heading and paragraph elements.";
        "files" = {
          "answer.md" = "# Answer\n\n42\n";
        };
        "input" = "A Markdown heading and paragraph containing the value 42.";
        "operation" = "Render the document as HTML through Lowdown.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lowdown"
              "-Thtml"
              "answer.md"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "<h1 id=\"answer\">Answer</h1>\n<p>42</p>\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lowdown rejects the formatter with status 1.";
        "files" = {
          "answer.md" = "42\n";
        };
        "input" = "A request for a Lowdown output format that does not exist.";
        "operation" = "Parse the unsupported formatter name.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lowdown"
              "-Tqualification-invalid"
              "answer.md"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://kristaps.bsd.lv/lowdown/snapshots/lowdown-${version}.tar.gz"
      ];
      hash = "sha256-WbLPNb8y/mAskvM66RenHgsup2pnu+SPuukBqO/G/vM=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lowdown-${version}
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # These headers only supplied types and declarations which the
              # bundled base64 fallback does not use.
              sed -i '/#include <arpa\/nameser\.h>/d; /#include <resolv\.h>/d' compats.c
            ''
            else ""
          }

          # Lowdown 3 uses bmake conditional syntax in an otherwise portable
          # makefile. Translate its three condition groups for GNU make.
          test "$(grep -c '^\.ifdef ' Makefile)" -eq 2
          test "$(grep -c '^\.if ' Makefile)" -eq 3
          sed -i \
            -e 's/^\.ifdef /ifdef /' \
            -e 's/^\.if $(SANDBOX_INIT_ERROR_IGNORE) == "always"$/ifeq ($(SANDBOX_INIT_ERROR_IGNORE),always)/' \
            -e 's/^\.if $(LINK_METHOD) == "shared"$/ifeq ($(LINK_METHOD),shared)/' \
            -e 's/^\.if $(LINKER_SOSUFFIX) == "dylib"$/ifeq ($(LINKER_SOSUFFIX),dylib)/' \
            -e 's/^\.else$/else/' \
            -e 's/^\.endif$/endif/' \
            Makefile
          test "$(grep -c '^ifeq ' Makefile)" -eq 3
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure PREFIX=$out
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              sed -i 's/liblowdown\.so/liblowdown.dylib/g' Makefile
              sed -i 's|-Wl,[^ ]* |-Wl,-install_name,@rpath/$@.$(LIBVER) |' Makefile
            ''
            else ""
          }
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
          make install install_shared
        '';
      }
    ];

    meta = {
      description = "lowdown — simple Markdown translator";
      homepage = "https://kristaps.bsd.lv/lowdown/";
      license = "ISC";
    };
  }
