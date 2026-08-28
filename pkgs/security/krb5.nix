##! MIT Kerberos — GSSAPI authentication and Kerberos network services
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  pkg-config,
  perl,
  openssl,
  bash,
  coreutils,
  writeShellScriptBin,
}: let
  version = "1.22.1";
  control = writeShellScriptBin "krb5-kdc-control" ''
    set -euo pipefail
    set -a
    source /etc/aos/packages/krb5-kdc/runtime.env
    set +a

    case "''${1:-}" in
      enabled) test "''${KRB5_KDC_ENABLED:-false}" = true ;;
      admin-enabled) test "''${KRB5_KADMIND_ENABLED:-false}" = true ;;
      prepare)
        if [[ ! -f /var/lib/aos-pkg-krb5-kdc/principal ]]; then
          password="''${CREDENTIALS_DIRECTORY:-}/master-password"
          [[ -r "$password" ]] || {
            echo "krb5 KDC database initialization requires master-password" >&2
            exit 1
          }
          /sbin/kdb5_util create -s -r "$KRB5_REALM" -P "$(<"$password")"
        fi
        ;;
      *) echo "usage: krb5-kdc-control {enabled|admin-enabled|prepare}" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "krb5";
    inherit version;

    src = fetchurl {
      urls = [
        "https://kerberos.org/dist/krb5/1.22/krb5-${version}.tar.gz"
      ];
      hash = "sha256-GogyuMrZI+u/E5T2fi789B46SfRgKFpm41reyPoAU68=";
    };

    buildDeps = [gnumake bison pkg-config perl];
    runtimeDeps = [openssl bash coreutils control];
    propagatedDeps = [];

    expose = {
      units = {
        "krb5-kdc-init.service" = {
          description = "Initialize the Kerberos KDC database";
          before = ["krb5-kdc.service" "kadmind.service"];
          restartIfChanged = true;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            EnvironmentFile = "/etc/aos/packages/krb5-kdc/runtime.env";
            ExecCondition = "/bin/krb5-kdc-control enabled";
            ExecStart = "/bin/krb5-kdc-control prepare";
            User = "krb5-kdc";
            Group = "krb5-kdc";
            StateDirectory = "aos-pkg-krb5-kdc";
            StateDirectoryMode = "0700";
            UMask = "0077";
          };
        };
        "krb5-kdc.service" = {
          description = "Kerberos key distribution center";
          after = ["network-online.target" "krb5-kdc-init.service"];
          wants = ["network-online.target"];
          requires = ["krb5-kdc-init.service"];
          restartIfChanged = true;
          stopOnRemoval = true;
          serviceConfig = {
            Type = "simple";
            EnvironmentFile = "/etc/aos/packages/krb5-kdc/runtime.env";
            ExecCondition = "/bin/krb5-kdc-control enabled";
            ExecStart = "/sbin/krb5kdc -n -P /run/aos-pkg-krb5-kdc/krb5kdc.pid";
            User = "krb5-kdc";
            Group = "krb5-kdc";
            StateDirectory = "aos-pkg-krb5-kdc";
            StateDirectoryMode = "0700";
            RuntimeDirectory = "aos-pkg-krb5-kdc";
            RuntimeDirectoryMode = "0750";
            LogsDirectory = "krb5-kdc";
            LogsDirectoryMode = "0750";
            Restart = "on-failure";
            UMask = "0077";
          };
        };
        "kadmind.service" = {
          description = "Kerberos administration daemon";
          after = ["network-online.target" "krb5-kdc-init.service"];
          wants = ["network-online.target"];
          requires = ["krb5-kdc-init.service"];
          restartIfChanged = true;
          stopOnRemoval = true;
          serviceConfig = {
            Type = "simple";
            EnvironmentFile = "/etc/aos/packages/krb5-kdc/runtime.env";
            ExecCondition = "/bin/krb5-kdc-control admin-enabled";
            ExecStart = "/sbin/kadmind -nofork -P /run/aos-pkg-krb5-kdc/kadmind.pid";
            User = "krb5-kdc";
            Group = "krb5-kdc";
            StateDirectory = "aos-pkg-krb5-kdc";
            StateDirectoryMode = "0700";
            RuntimeDirectory = "aos-pkg-krb5-kdc";
            RuntimeDirectoryMode = "0750";
            LogsDirectory = "krb5-kdc";
            LogsDirectoryMode = "0750";
            Restart = "on-failure";
            UMask = "0077";
          };
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/krb5-kdc/runtime.env";
            format = "env";
            required = ["KRB5_KADMIND_ENABLED" "KRB5_KDC_ENABLED" "KRB5_REALM"];
            units = ["krb5-kdc-init.service" "krb5-kdc.service" "kadmind.service"];
            reload = "restart";
          }
        ];
        credentials = [
          {
            name = "master-password";
            source = "/run/credstore/krb5-kdc/master-password";
            units = ["krb5-kdc-init.service"];
            encrypted = false;
            optional = true;
          }
        ];
      };
      firewall = {
        allowedTCP = [88 749];
        allowedUDP = [88];
      };
      permissions = {
        network = "host";
        capabilities = ["CAP_NET_BIND_SERVICE"];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/krb5-kdc";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-krb5-kdc";
      };
    };

    configModule = {
      src = ./_krb5-kdc-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "krb5Kdc.acl"
        "krb5Kdc.adminServer"
        "krb5Kdc.enable"
        "krb5Kdc.enableAdminServer"
        "krb5Kdc.kdcServers"
        "krb5Kdc.masterPassword"
        "krb5Kdc.maxLife"
        "krb5Kdc.maxRenewableLife"
        "krb5Kdc.realm"
      ];
      ownsRoots = [
        {
          root = "krb5Kdc";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = [
          "aos/packages/krb5-kdc/krb5.conf"
          "aos/packages/krb5-kdc/kdc.conf"
          "aos/packages/krb5-kdc/kadm5.acl"
        ];
        units = [];
        users = ["krb5-kdc"];
        groups = ["krb5-kdc"];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd krb5-${version}/src
        '';
      }
      {
        name = "configure";
        script = ''
          YACC='bison -y' ./configure \
            --prefix=$out \
            --enable-shared \
            --with-crypto-impl=openssl \
            --with-tls-impl=openssl
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
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-krb5-config";
        tool = self;
        command = "krb5-config --version";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libkrb5.so" "libgssapi_krb5.so"];
      };

      config = let
        evaluated = lib.evalModules {
          inherit lib;
          modules = [
            ({lib, ...}: {
              options = {
                assertions = lib.mkOption {
                  type = lib.types.listOf lib.types.attrs;
                  default = [];
                };
                "krb5-kdc".config = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                  default = {};
                };
                "krb5-kdc".credentials = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                environment.etc = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                users.users = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                users.groups = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
              };
            })
            ./_krb5-kdc-config/module.nix
            {
              krb5Kdc = {
                enable = true;
                realm = "EXAMPLE.TEST";
                kdcServers = ["kdc.example.test"];
                adminServer = "kdc.example.test";
                masterPassword.ref = "system-credential:krb5-master";
              };
            }
          ];
        };
      in
        pkgs.runCommand "krb5-kdc-config-module" {} ''
          krb5=${builtins.toFile "krb5.conf" evaluated.config.environment.etc."aos/packages/krb5-kdc/krb5.conf".text}
          kdc=${builtins.toFile "kdc.conf" evaluated.config.environment.etc."aos/packages/krb5-kdc/kdc.conf".text}
          grep -F 'default_realm = EXAMPLE.TEST' "$krb5"
          grep -F 'kdc = kdc.example.test' "$krb5"
          grep -F 'max_life = 10h' "$kdc"
          test '${evaluated.config."krb5-kdc".credentials.master-password.ref}' = 'system-credential:krb5-master'
          touch "$out"
        '';
    };

    meta = {
      description = "MIT Kerberos and GSSAPI implementation";
      homepage = "https://web.mit.edu/kerberos/";
      license = "MIT";
    };
  }
