##! jq — Lightweight command-line JSON processor
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  oniguruma,
  buildPackages,
}: let
  upstream = mkGithubUpstream {
    unitId = "jq-1";
    family = "jq";
    stream = "1";
    owner = "pkgs/tools/jq.nix";
    version = "1.8.2";
    upstreamId = "jq-1.8.2";
    repository = "jqlang/jq";
    provider = "github-releases";
    tagPrefix = "jq-";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "jqlang"
        "jq"
        "releases"
        "download"
        {
          parts = [
            {literal = "jq-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "jq-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-cbjW6PX+gfbG0NEQ44kiUfbOdu0JWr0xXibm4Rk6868=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "jq";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "jq emits the canonical integer result 42.";
        "files" = {};
        "input" = "A JSON object whose answer member is 41.";
        "operation" = "Parse the document and increment its answer with a jq filter.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/jq"
              ".answer + 1"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "{\"answer\":41}\n";
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "jq exits with its invalid-JSON status.";
        "files" = {};
        "input" = "A truncated JSON object.";
        "operation" = "Parse the malformed document with the identity filter.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/jq"
              "."
            ];
            "exit_code" = 5;
            "observes_rejection" = true;
            "stdin" = "{\"answer\":";
          }
        ];
      };
    };

    inherit version;
    outputs = ["out" "dev"];

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [oniguruma];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of jq's
    # `--version`-baked PKG_CONFIG_PATH / CC strings.
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jq-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-maintainer-mode \
            --with-oniguruma
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

          # Containers need jq and its shared library, while downstream builds
          # retain the public headers, static archive, and linker metadata.
          mkdir -p "$dev/lib"
          mv "$out/include" "$dev/include"
          mv "$out/lib/pkgconfig" "$dev/lib/pkgconfig"
          for library in "$out/lib/"*.a "$out/lib/"*.la; do
            if [ -f "$library" ]; then
              mv "$library" "$dev/lib/"
            fi
          done
          for library in "$out/lib/libjq.so" "$out/lib/libjq.dylib"; do
            if [ -L "$library" ]; then
              target=$(readlink "$library")
              name=$(basename "$library")
              rm "$library"
              ln -s "$out/lib/$target" "$dev/lib/$name"
            fi
          done

          sed -i \
            -e "s|^prefix=.*|prefix=$dev|" \
            -e "s|^libdir=.*|libdir=$dev/lib|" \
            -e "s|^includedir=.*|includedir=$dev/include|" \
            "$dev/lib/pkgconfig/libjq.pc"
          if [ -f "$dev/lib/libjq.la" ]; then
            sed -i "s|^libdir=.*|libdir='$dev/lib'|" "$dev/lib/libjq.la"
          fi
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["jq"];
      };

      dynamic-linker = testing.mkDynLinkerCheck {
        pkg = self;
        bins = ["jq"];
      };

      version = testing.mkToolCheck {
        pname = "tool-jq";
        tool = self;
        command = "jq --version";
      };

      query = testing.mkVMTest {
        name = "tool-jq-query";
        rootfsDeps = [self];
        testScript = ''
          echo '{"a":1}' > /tmp/input.json
          RESULT=$(jq '.a' /tmp/input.json)
          if [ "$RESULT" != "1" ]; then
            echo "FAIL: expected 1, got $RESULT" >&2
            exit 1
          fi
          echo "==> jq query: passed"
        '';
      };
    };

    meta = {
      description = "Lightweight command-line JSON processor";
      homepage = "https://jqlang.github.io/jq/";
      license = "MIT";
    };
  }
