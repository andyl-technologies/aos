##! conntrack-tools — Connection tracking userspace tools for netfilter
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnetfilter_cthelper,
  libnetfilter_cttimeout,
  libnetfilter_queue,
  libtirpc,
  writeShellScriptBin,
}: let
  version = "1.4.8";
  control = writeShellScriptBin "conntrackd-control" ''
    set -eu
    case "''${1:-}" in
      enabled) test "''${CONNTRACKD_ENABLED:-false}" = true ;;
      *) echo "usage: conntrackd-control enabled" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "conntrack-tools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-${version}.tar.xz"
      ];
      hash = "sha256-BnZ39MX2VkgZ547TqdSomAk16pJz86uyKkIOowq13tY=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
      libnetfilter_conntrack
      libnetfilter_cthelper
      libnetfilter_cttimeout
      libnetfilter_queue
      libtirpc
      control
    ];
    propagatedDeps = [];

    expose = {
      units."conntrackd.service" = {
        description = "Connection tracking state daemon";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "notify";
          EnvironmentFile = "/etc/aos/packages/conntrackd/runtime.env";
          ExecCondition = "/bin/conntrackd-control enabled";
          ExecStart = "/sbin/conntrackd -C /etc/aos/packages/conntrackd/conntrackd.conf -d";
          ExecReload = "/sbin/conntrackd -C /etc/aos/packages/conntrackd/conntrackd.conf -R";
          RuntimeDirectory = "aos-pkg-conntrackd";
          RuntimeDirectoryMode = "0750";
          LogsDirectory = "conntrackd";
          LogsDirectoryMode = "0750";
          Restart = "on-failure";
          UMask = "0027";
        };
      };
      config.artifacts = [
        {
          name = "runtime";
          path = "/etc/aos/packages/conntrackd/runtime.env";
          format = "env";
          required = ["CONNTRACKD_ENABLED"];
          units = ["conntrackd.service"];
          reload = "restart";
        }
      ];
      permissions = {
        network = "host";
        capabilities = ["CAP_NET_ADMIN" "CAP_NET_RAW"];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/conntrackd/conntrackd.conf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-conntrackd";
      };
    };

    configModule = {
      src = ./_conntrackd-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "conntrackd.enable"
        "conntrackd.hashLimit"
        "conntrackd.hashSize"
        "conntrackd.logConnections"
        "conntrackd.mode"
        "conntrackd.netlinkBufferSize"
        "conntrackd.pollSeconds"
        "conntrackd.sync"
      ];
      ownsRoots = [
        {
          root = "conntrackd";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/conntrackd/conntrackd.conf"];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "Typed conntrackd cache, polling, logging, and state-synchronization configuration.";
        sections = {
          modes = lib.aosDoc.section "Operation modes" [
            (lib.aosDoc.paragraph "Choose a local statistics/cache mode or declare a complete synchronization channel. Buffer, hash, polling, and connection logging controls are validated before reload.")
          ];
          lifecycle = lib.aosDoc.section "Runtime lifecycle" [
            (lib.aosDoc.paragraph "conntrackd reloads a validated configuration in place while its socket and log paths remain systemd-managed.")
          ];
        };
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd conntrack-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static
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
      description = "conntrack-tools — connection tracking userspace tools for netfilter";
      homepage = "https://www.netfilter.org/projects/conntrack-tools/";
      license = "GPL-2.0-or-later";
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
              conntrackd.config = lib.mkOption {
                type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                default = {};
              };
              environment.etc = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
            };
          })
          ./_conntrackd-config/module.nix
          {
            conntrackd = {
              enable = true;
              mode = "sync";
              sync = {
                interface = "eth1";
                localAddress = "192.0.2.10";
                peerAddress = "192.0.2.11";
              };
            };
          }
        ];
      };
    in {
      config = pkgs.runCommand "conntrackd-config-module" {} ''
        config=${builtins.toFile "conntrackd.conf" evaluated.config.environment.etc."aos/packages/conntrackd/conntrackd.conf".text}
        grep -F 'Mode FTFW' "$config"
        grep -F 'IPv4_address 192.0.2.10' "$config"
        grep -F 'IPv4_Destination_Address 192.0.2.11' "$config"
        test '${toString evaluated.config.conntrackd.config.runtime.CONNTRACKD_ENABLED}' = '1'
        test -x ${self}/sbin/conntrackd
        touch "$out"
      '';
    };
  }
