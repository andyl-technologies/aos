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
      declares = [
        "openldap.database.maxBytes"
        "openldap.enable"
        "openldap.listenUrls"
        "openldap.rootDn"
        "openldap.rootPassword"
        "openldap.suffix"
        "openldap.tls.certificate"
        "openldap.tls.enable"
        "openldap.tls.privateKey"
        "openldap.tls.trustedCa"
        "openldap.tls.verifyClient"
      ];
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
      documentation = {
        summary = "OpenLDAP client libraries, tools, and directory server";
        sections = {
          directory = lib.aosDoc.section "Directory state" [
            (lib.aosDoc.paragraph "The suffix and root DN define a durable package-owned database. Changing identity fields does not migrate existing directory data automatically.")
          ];
          credentials = lib.aosDoc.section "Credentials and TLS" [
            (lib.aosDoc.paragraph "Root password and TLS key material use opaque references delivered through service credentials; plaintext values are not accepted by the module.")
          ];
        };
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
      pkgs,
      ...
    }: let
      evaluate = openldapConfig:
        lib.evalModules {
          inherit lib;
          modules = [
            ({lib, ...}: {
              options = {
                assertions = lib.mkOption {
                  type = lib.types.listOf lib.types.attrs;
                  default = [];
                };
                openldap.config = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                  default = {};
                };
                openldap.credentials = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                environment.etc = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                aos.users.users = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                aos.users.groups = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
              };
            })
            ./_openldap-config/module.nix
            {openldap = openldapConfig;}
          ];
        };
      valid = evaluate {
        enable = true;
        suffix = "dc=aos,dc=test";
        rootDn = "cn=admin,dc=aos,dc=test";
        rootPassword.ref = "system-credential:openldap-root-password";
      };
      missingPassword = evaluate {enable = true;};
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      rendered = builtins.toFile "openldap-slapd.conf" valid.config.environment.etc."aos/packages/openldap/slapd.conf".text;
    in {
      cli = testing.mkToolCheck {
        pname = "tool-openldap";
        tool = self;
        command = "slapd -VV";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libldap.so" "liblber.so"];
      };

      config = assert assertionsHold valid;
      assert !assertionsHold missingPassword;
        pkgs.runCommand "openldap-config-module" {} ''
          cp ${rendered} slapd.conf
          ${pkgs.sed}/bin/sed -i \
              -e 's#/etc/openldap#${self}/etc/openldap#g' \
              -e 's#/libexec/openldap#${self}/libexec/openldap#g' \
              -e "s#/run/aos-pkg-openldap#$TMPDIR/run#g" \
              -e "s#/var/lib/aos-pkg-openldap/data#$TMPDIR/data#g" \
              slapd.conf
            mkdir -p "$TMPDIR/data" "$TMPDIR/run"
          ${self}/sbin/slaptest -u -f slapd.conf
          grep -F 'suffix "dc=aos,dc=test"' slapd.conf
          test '${valid.config.openldap.credentials."root-password".ref}' = \
            'system-credential:openldap-root-password'
          touch "$out"
        '';

      config-lifecycle = testing.mkVMTest {
        name = "networking-openldap-config-lifecycle";
        rootfsDeps = [self rendered pkgs.grep pkgs.iproute2 pkgs.sed];
        testScript = ''
          ${pkgs.iproute2}/sbin/ip link set lo up
          mkdir -p /var/lib/aos-pkg-openldap/data /run/aos-pkg-openldap
          cp ${rendered} /tmp/slapd.conf
          ${pkgs.sed}/bin/sed -i \
            -e 's#/etc/openldap#${self}/etc/openldap#g' \
            -e 's#/libexec/openldap#${self}/libexec/openldap#g' \
            /tmp/slapd.conf
          printf 'rootpw %s\n' "$(${self}/sbin/slappasswd -s aos-test-password)" >> /tmp/slapd.conf
          ${self}/sbin/slaptest -u -f /tmp/slapd.conf

          start_slapd() {
            ${self}/libexec/slapd -d 0 -f /tmp/slapd.conf -h ldap://127.0.0.1:1389/ >/tmp/slapd.log 2>&1 &
            slapd_pid=$!
            ready=false
            for attempt in 1 2 3 4 5 6 7 8 9 10; do
              if ${self}/bin/ldapsearch -x -H ldap://127.0.0.1:1389 -s base -b "" namingContexts >/dev/null 2>&1; then
                ready=true
                break
              fi
              sleep 1
            done
            if [ "$ready" != true ]; then
              cat /tmp/slapd.log >&2
              exit 1
            fi
          }

          start_slapd
          printf '%s\n' \
            'dn: dc=aos,dc=test' \
            'objectClass: top' \
            'objectClass: domain' \
            'dc: aos' \
            > /tmp/base.ldif
          ${self}/bin/ldapadd -x -H ldap://127.0.0.1:1389 \
            -D 'cn=admin,dc=aos,dc=test' -w aos-test-password \
            -f /tmp/base.ldif
          ${self}/bin/ldapsearch -x -H ldap://127.0.0.1:1389 \
            -b 'dc=aos,dc=test' '(objectClass=domain)' dc \
            | ${pkgs.grep}/bin/grep -F 'dc: aos'
          kill "$slapd_pid"
          wait "$slapd_pid" || true

          start_slapd
          ${self}/bin/ldapsearch -x -H ldap://127.0.0.1:1389 \
            -b 'dc=aos,dc=test' '(objectClass=domain)' dc \
            | ${pkgs.grep}/bin/grep -F 'dc: aos'
          kill "$slapd_pid"
          wait "$slapd_pid" || true

          cp /tmp/slapd.conf /tmp/slapd-invalid.conf
          printf '%s\n' 'unknown-directive true' >> /tmp/slapd-invalid.conf
          if ${self}/sbin/slaptest -u -f /tmp/slapd-invalid.conf >/tmp/invalid.log 2>&1; then
            echo 'OpenLDAP accepted an unknown configuration directive' >&2
            exit 1
          fi
          echo 'OpenLDAP typed config and real-binary lifecycle: PASS'
        '';
      };
    };

    meta = {
      description = "OpenLDAP client libraries, tools, and directory server";
      homepage = "https://www.openldap.org/";
      license = "OLDAP-2.8";
    };
  }
