##! jq — Lightweight command-line JSON processor
{
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
    pname = "jq";
    inherit version;

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
