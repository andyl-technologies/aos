##! rsync — Fast incremental file transfer
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  openssl,
  zstd,
  lz4,
  bash,
  stdenv,
  service-management,
  aos-filesystem-provider,
}: let
  version = "3.5.0";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "rsync";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "destination.txt";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "The destination contains the source bytes exactly.";
        "files" = {
          "source.txt" = "answer=42\n";
        };
        "input" = "A source file with a fixed payload.";
        "operation" = "Copy the file locally through rsync's transfer engine.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rsync"
              "--quiet"
              "source.txt"
              "destination.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Rsync rejects the missing source with its partial-transfer status.";
        "files" = {};
        "input" = "A source path that does not exist.";
        "operation" = "Attempt a local transfer from the missing source.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rsync"
              "--quiet"
              "missing.txt"
              "destination.txt"
            ];
            "exit_code" = 23;
            "observes_rejection" = true;
          }
        ];
      };
    };

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    src = fetchurl {
      urls = [
        "https://download.samba.org/pub/rsync/src/rsync-${version}.tar.gz"
      ];
      hash = "sha256-x//R72U+mVQPZh5HywC3+crR7muXI5mxb5PWcmVuDTM=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [
        zlib
        openssl
        zstd
        lz4
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    module = ./_rsyncd;
    moduleDeps = [service-management aos-filesystem-provider];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rsync-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-included-popt \
            --with-included-zlib=no \
            --disable-xxhash \
            --enable-zstd \
            --enable-lz4 \
            --disable-md2man
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
            if [ -f "$out/bin/rsync-ssl" ]; then
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/rsync-ssl"
            fi
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "rsync — fast incremental file transfer";
      homepage = "https://rsync.samba.org/";
      license = "GPL-3.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      credential = "rsync-secrets";
      evaluate = settings:
        lib.evalPackageModules {
          scope = ["package-check" "rsyncd"];
          packages = [self];
          operatorModules = [{aos.rsyncd = settings;}];
        };
      evaluated = evaluate {
        enable = true;
        modules.public = {};
      };
      authenticated = evaluate {
        enable = true;
        modules.private.authUsers = ["backup"];
        secrets.name = credential;
      };
      invalid = evaluate {
        enable = true;
        modules.private.authUsers = ["backup"];
      };
      nativeTests = import ./_rsyncd/native-tests.nix {inherit lib evaluated authenticated invalid;};
      contractHolds = builtins.all (value: value) (builtins.attrValues nativeTests);
    in {
      version = testing.mkToolCheck {
        pname = "tool-rsync";
        tool = self;
        command = "rsync --version";
      };

      native-module-contract =
        if contractHolds
        then
          pkgs.runCommand "rsyncd-native-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the rsyncd native module checks failed";
    };
  }
