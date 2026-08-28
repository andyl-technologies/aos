##! OpenLDAP — LDAP client libraries, tools, and directory server
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libtool,
  cyrus-sasl,
  krb5,
  openssl,
  bash,
  coreutils,
  writeShellScriptBin,
}: let
  version = "2.6.10";
  control = writeShellScriptBin "openldap-control" ''
    set -euo pipefail
    case "''${1:-}" in
      enabled) test "''${OPENLDAP_ENABLED:-false}" = true ;;
      prepare)
        install -d -m 0700 /var/lib/aos-pkg-openldap/data /run/aos-pkg-openldap
        base=/etc/aos/packages/openldap/slapd.conf
        runtime=/run/aos-pkg-openldap/slapd.conf
        password="''${CREDENTIALS_DIRECTORY:?}/root-password"
        test -s "$password"
        cat "$base" > "$runtime"
        printf 'rootpw {CLEARTEXT}%s\n' "$(cat "$password")" >> "$runtime"
        chmod 0600 "$runtime"
        /sbin/slaptest -u -f "$runtime"
        ;;
      *) echo "usage: openldap-control {enabled|prepare}" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "openldap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${version}.tgz"
      ];
      hash = "sha256-wGXwSq1Cc3rr1gsv5JOXBKyEQma8CuqhYJ8MrZh75RY=";
    };

    buildDeps = [gnumake pkg-config libtool];
    runtimeDeps = [cyrus-sasl krb5 openssl libtool bash coreutils control];
    propagatedDeps = [];

    expose = {
      units."openldap.service" = {
        description = "OpenLDAP directory server";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "simple";
          User = "openldap";
          Group = "openldap";
          EnvironmentFile = "/etc/aos/packages/openldap/runtime.env";
          ExecCondition = "/bin/openldap-control enabled";
          ExecStartPre = "/bin/openldap-control prepare";
          ExecStart = "/libexec/slapd -d 0 -f /run/aos-pkg-openldap/slapd.conf -h $OPENLDAP_LISTEN_URLS";
          StateDirectory = "aos-pkg-openldap";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-pkg-openldap";
          RuntimeDirectoryMode = "0700";
          Restart = "on-failure";
          UMask = "0077";
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/openldap/runtime.env";
            format = "env";
            required = ["OPENLDAP_CONFIG_GENERATION" "OPENLDAP_ENABLED" "OPENLDAP_LISTEN_URLS"];
            units = ["openldap.service"];
            reload = "restart";
          }
        ];
        credentials = builtins.map (name: {
          inherit name;
          source = "/run/credstore/openldap/${name}";
          units = ["openldap.service"];
          encrypted = false;
          optional = name != "root-password";
        }) ["root-password" "tls-certificate" "tls-private-key" "tls-ca"];
      };
      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/openldap/slapd.conf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-openldap";
      };
    };

    configModule = {
      src = ./_openldap-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = ["openldap.database.maxBytes" "openldap.enable" "openldap.listenUrls" "openldap.rootDn" "openldap.rootPassword" "openldap.suffix" "openldap.tls"];
      ownsRoots = [
        {
          root = "openldap";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/openldap/slapd.conf"];
        units = [];
        users = ["openldap"];
        groups = ["openldap"];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openldap-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-dynamic \
            --enable-modules \
            --enable-slapd \
            --enable-overlays=mod \
            --with-cyrus-sasl \
            --with-tls=openssl
        '';
      }
      {
        name = "build";
        script = ''
          # OpenLDAP uses soelim only to flatten pre-generated manual pages.
          # Supply the same hermetic passthrough used by other AOS packages;
          # no host groff tooling is consulted.
          mkdir -p .aos-build-tools
          printf '#!%s\nexec cat "$@"\n' "$CONFIG_SHELL" > .aos-build-tools/soelim
          chmod +x .aos-build-tools/soelim
          export PATH="$PWD/.aos-build-tools:$PATH"
          make -j$NIX_BUILD_CORES depend
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
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-openldap";
        tool = self;
        command = "slapd -VV";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libldap.so" "liblber.so"];
      };
    };

    meta = {
      description = "OpenLDAP client libraries, tools, and directory server";
      homepage = "https://www.openldap.org/";
      license = "OLDAP-2.8";
    };
  }
