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
  writeShellScriptBin,
}: let
  version = "3.4.1";
  control = writeShellScriptBin "rsyncd-control" ''
    set -eu
    case "''${1:-}" in
      enabled) test "''${RSYNCD_ENABLED:-false}" = true ;;
      prepare)
        for module in /var/lib/aos-pkg-rsyncd/exports/*; do
          test -e "$module" || continue
          test -d "$module" || exit 1
        done
        ;;
      *) echo "usage: rsyncd-control {enabled|prepare}" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "rsync";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.samba.org/pub/rsync/src/rsync-${version}.tar.gz"
      ];
      hash = "sha256-KSS8s6Hti1UfwQH3QLnw/gogKxFQJ2R89phQ1l/YjFI=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [
      control
      zlib
      openssl
      zstd
      lz4
    ];
    propagatedDeps = [];

    expose = {
      units."rsyncd.service" = {
        description = "Rsync file-transfer daemon";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "simple";
          DynamicUser = true;
          EnvironmentFile = "/etc/aos/packages/rsyncd/runtime.env";
          ExecCondition = "/bin/rsyncd-control enabled";
          ExecStartPre = "/bin/rsyncd-control prepare";
          ExecStart = "/bin/rsync --daemon --no-detach --config=/etc/aos/packages/rsyncd/rsyncd.conf --address=$RSYNCD_ADDRESS --port=$RSYNCD_PORT";
          StateDirectory = "aos-pkg-rsyncd";
          StateDirectoryMode = "0750";
          RuntimeDirectory = "aos-pkg-rsyncd";
          RuntimeDirectoryMode = "0750";
          LogsDirectory = "rsyncd";
          LogsDirectoryMode = "0750";
          Restart = "on-failure";
          UMask = "0027";
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/rsyncd/runtime.env";
            format = "env";
            required = ["RSYNCD_ADDRESS" "RSYNCD_CONFIG_GENERATION" "RSYNCD_ENABLED" "RSYNCD_PORT"];
            units = ["rsyncd.service"];
            reload = "restart";
          }
        ];
        credentials = [
          {
            name = "secrets-file";
            source = "/run/credstore/rsyncd/secrets-file";
            units = ["rsyncd.service"];
            encrypted = false;
            optional = true;
          }
        ];
      };
      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/rsyncd/rsyncd.conf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-rsyncd";
      };
    };

    configModule = {
      src = ./_rsyncd-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = ["rsyncd.address" "rsyncd.enable" "rsyncd.modules" "rsyncd.port" "rsyncd.secrets"];
      ownsRoots = [
        {
          root = "rsyncd";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/rsyncd/rsyncd.conf"];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "rsync — fast incremental file transfer";
        sections = {
          exports = lib.aosDoc.section "Export modules" [
            (lib.aosDoc.paragraph "Each named module declares an explicit package state export path and read/write policy. Module names, paths, and client restrictions are validated before activation.")
          ];
          credentials = lib.aosDoc.section "Authentication" [
            (lib.aosDoc.paragraph "Daemon secret files are assembled from opaque references in volatile storage and are never represented as Nix strings or published artifacts.")
          ];
        };
      };
    };

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
        script = ''
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
    }: let
      evaluated = lib.evalModules {
        inherit lib;
        modules = [
          ({lib, ...}: {
            options = {
              assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
              };
              rsyncd.config = lib.mkOption {
                type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                default = {};
              };
              rsyncd.credentials = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
              environment.etc = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
            };
          })
          ./_rsyncd-config/module.nix
          {
            rsyncd = {
              enable = true;
              modules.public = {};
            };
          }
        ];
      };
    in {
      version = testing.mkToolCheck {
        pname = "tool-rsync";
        tool = self;
        command = "rsync --version";
      };

      config = pkgs.runCommand "rsyncd-config-module" {} ''
          config=${builtins.toFile "rsyncd.conf" evaluated.config.environment.etc."aos/packages/rsyncd/rsyncd.conf".text}
          cp "$config" ./rsyncd.conf
          config=./rsyncd.conf
          mkdir -p "$TMPDIR/exports/public" "$TMPDIR/log" "$TMPDIR/run"
          sed -i \
            -e "s#/run/aos-pkg-rsyncd#$TMPDIR/run#g" \
            -e "s#/var/log/rsyncd#$TMPDIR/log#g" \
            -e "s#/var/lib/aos-pkg-rsyncd/exports#$TMPDIR/exports#g" \
            "$config"
          grep -F '[public]' "$config"
          grep -F "path = $TMPDIR/exports/public" "$config"
        ${self}/bin/rsync --daemon --config="$config" --address=127.0.0.1 --port=18730 --no-detach &
        pid=$!
        sleep 1
        kill "$pid"
        wait "$pid" || true
        touch "$out"
      '';
    };
  }
