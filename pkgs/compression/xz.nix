##! XZ Utils — LZMA compression utilities
{
  lib,
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
    version = "5.8.3";
    upstreamId = "v5.8.3";
    repository = "tukaani-project/xz";
    provider = "github-releases";
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
      hash = "sha256-//H/zysNqE0wihTeUToaoj1OmqNGTRfmS5cUv90Lv7Y=";
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
    pname = "xz";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The decoded bytes exactly reproduce the original payload.";
        "files" = {
          "payload.txt" = "AOS qualification payload\n";
        };
        "input" = "A fixed text payload.";
        "operation" = "Compress the payload, then decode the resulting xz stream.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xz"
              "-q"
              "payload.txt"
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
              "@out@/bin/xz"
              "-q"
              "-d"
              "-c"
              "payload.txt.xz"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "AOS qualification payload\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The decoder rejects bytes outside the xz format.";
        "files" = {
          "invalid.xz" = "not a compressed stream\n";
        };
        "input" = "A plain-text file carrying a xz filename suffix.";
        "operation" = "Attempt to decode the malformed compressed stream.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xz"
              "-q"
              "-d"
              "-c"
              "invalid.xz"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

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
