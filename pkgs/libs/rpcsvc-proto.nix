##! rpcsvc-proto — RPC service protocol definitions and rpcgen
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  buildPackages,
  stdenv,
  gcc,
}: let
  version = "1.4.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "rpcsvc-proto";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The header declares the answer structure and its XDR function.";
        "files" = {
          "answer.x" = "struct answer {\n    int value;\n};\n";
          "verify.py" = "content = open(\"answer.h\", encoding=\"utf-8\").read()\nrequired = [\"struct answer\",\"xdr_answer\"]\nassert all(fragment in content for fragment in required)\nprint(\"rpcgen output passed\")\n";
        };
        "input" = "An RPC language definition containing one structure and XDR procedure.";
        "operation" = "Generate its public C declarations with rpcgen and inspect the emitted interface.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rpcgen"
              "-h"
              "-o"
              "answer.h"
              "answer.x"
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
              "@python@"
              "verify.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "rpcgen output passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "rpcgen rejects the syntax error without producing a usable header.";
        "files" = {
          "invalid.x" = "struct answer { int value };\n";
        };
        "input" = "An RPC structure whose field declaration lacks a semicolon.";
        "operation" = "Parse the malformed RPC definition.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rpcgen"
              "-h"
              "-o"
              "invalid.h"
              "invalid.x"
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
        "https://github.com/thkukuk/rpcsvc-proto/releases/download/v${version}/rpcsvc-proto-${version}.tar.xz"
      ];
      hash = "sha256-gcOqJ+212KGO8CcIHruYQjTVtYYMZb2Z1KyPAxRaVYs=";
    };

    buildDeps =
      [
        gnumake
        gettext
      ]
      ++ (
        if stdenv.isCross
        then [buildPackages.rpcsvc-proto]
        else [gcc]
      );
    runtimeDeps = [gettext gcc];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rpcsvc-proto-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # The installed generator requires a real target-hosted preprocessor,
          # independently of the build-local launcher used to generate headers.
          sed -i 's|"/lib/cpp"|"${gcc}/bin/cpp"|' rpcgen/rpc_main.c

          ./configure \
            $configureFlags \
            --prefix=$out

          # rpcgen otherwise searches /lib/cpp and then PATH for a standalone
          # cpp binary. The AOS compiler is intentionally exposed through its
          # wrapper instead, so provide a build-local preprocessor launcher.
          build_cpp="$CC"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            build_cpp="$CC_FOR_BUILD"
          fi
          mkdir -p build-tools
          cat > build-tools/cpp <<EOF
          #!$CONFIG_SHELL
          AOS_HARDENING_ENABLE= \
          C_INCLUDE_PATH= \
          CPLUS_INCLUDE_PATH= \
          LIBRARY_PATH= \
            exec "$build_cpp" -E "\$@"
          EOF
          chmod +x build-tools/cpp
          sed -i \
            's| -h -o| -Y $(top_builddir)/build-tools -h -o|' \
            rpcsvc/Makefile

          ${
            if stdenv.isCross
            then ''
              # rpcsvc header generation executes rpcgen during `make`.
              # Generate with the native tool while still building and
              # installing the complete Darwin rpcgen executable.
              sed -i \
                's|$(top_builddir)/rpcgen/rpcgen|${buildPackages.rpcsvc-proto}/bin/rpcgen|g' \
                rpcsvc/Makefile
            ''
            else ""
          }

          grep '^USE_NLS = yes$' Makefile
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
      description = "RPC service protocol definitions and rpcgen compiler";
      homepage = "https://github.com/thkukuk/rpcsvc-proto";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      rpcgen = testing.mkToolCheck {
        pname = "tool-rpcgen";
        tool = self;
        command = "rpcgen --help";
      };

      catalogs = testing.mkVMTest {
        name = "lib-rpcsvc-proto-nls";
        rootfsDeps = [self];
        testScript = ''
          test -d ${self}/share/locale
          find ${self}/share/locale -type f -name '*.mo' | grep .
        '';
      };
    };
  }
