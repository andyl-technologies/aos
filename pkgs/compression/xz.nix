##! XZ Utils — LZMA compression utilities
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "xz-5";
    family = "xz";
    stream = "5";
    owner = "pkgs/compression/xz.nix";
    version = "5.8.2";
    upstreamId = "v5.8.2";
    repository = "tukaani-project/xz";
    tagPrefix = "v";
    major = 5;
    source = {
      authority = "github.com";
      path = [
        "tukaani-project"
        "xz"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
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
            {literal = "xz-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.xz";}
          ];
        }
      ];
      hash = "sha256-iQlm7D9dXMFRB3h54VfAWTUApSL0E6xQuibSKpoUUhQ=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "xz";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd xz-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Mach-O debug symbols retain compilation and object paths even
              # after stripping. Remap the sandbox prefix at compile time so
              # cached libraries contain no ephemeral /build references.
              export CFLAGS="''${CFLAGS:-} -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."
            ''
            else ""
          }

          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-nls \
            --disable-static \
            --enable-shared
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
      roundtrip = testing.mkVMTest {
        name = "tool-xz-roundtrip";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          echo "xz test data" > /tmp/xz-test.txt
          xz /tmp/xz-test.txt
          test -f /tmp/xz-test.txt.xz
          test ! -f /tmp/xz-test.txt
          xz -d /tmp/xz-test.txt.xz
          test "$(cat /tmp/xz-test.txt)" = "xz test data"
          echo "==> xz roundtrip: passed"
        '';
      };
    };

    meta = {
      description = "XZ Utils — LZMA compression utilities";
      homepage = "https://tukaani.org/xz/";
      license = "GPL-2.0-or-later";
    };
  }
