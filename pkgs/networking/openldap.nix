##! OpenLDAP — LDAP client libraries, tools, and directory server
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  file,
  libtool,
  cyrus-sasl,
  krb5,
  openssl,
  buildPackages,
  stdenv,
  bash,
  coreutils,
}: let
  version = "2.7.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "openldap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${version}.tgz"
      ];
      hash = "sha256-nobzfaN1qpSKG0eN12/oewIJDkfCH6yuGSI1iONAeSI=";
    };

    buildDeps = [gnumake pkg-config file libtool];
    runtimeDeps = [cyrus-sasl krb5 openssl libtool bash coreutils];
    propagatedDeps = [];

    abilities = ./_openldap/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openldap-${version}

          # Libtool's generated configure probe must use AOS's native file
          # utility; the upstream FHS path is neither present nor permitted.
          sed -i 's|/usr/bin/file|${buildPackages.file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
            # Autoconf pessimistically selects OpenLDAP's internal memcmp
            # replacement whenever it cannot execute a target probe.  That
            # replacement lives in the server-only liblutil archive, leaving
            # the public Darwin libldap dylib with an unresolved
            # lutil_memcmp. Darwin's libc memcmp is conforming.
            ac_cv_func_memcmp_working=yes ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-dynamic \
              --enable-modules \
              --enable-slapd \
              --enable-overlays=mod \
              --with-cyrus-sasl \
              --with-tls=openssl \
              --with-yielding-select=yes

            # OpenLDAP's bundled Libtool predates macOS 11, so its deployment
            # target case leaves allow_undefined_flag empty.  Slapd backends
            # and overlays are bundles whose host symbols are intentionally
            # resolved when slapd loads them; keep ordinary dylibs strict and
            # restore dynamic lookup only for Libtool's module commands.
            sed -i \
              -e '/^module_cmds=/s/$allow_undefined_flag/-Wl,-undefined,dynamic_lookup/' \
              -e '/^module_expsym_cmds=/s/$allow_undefined_flag/-Wl,-undefined,dynamic_lookup/' \
              libtool
          ''
          else ''
            ./configure \
              $configureFlags \
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
          # Upstream's version generator otherwise embeds the sandbox hostname
          # and build directory into every client and server executable.
          SOURCE_DATE_EPOCH=1
          export SOURCE_DATE_EPOCH

          # OpenLDAP expands shared roff fragments while generating its manual
          # pages.  AOS does not yet package groff's soelim, so provide the
          # small part of its behavior used here instead of dropping the docs.
          mkdir -p "$TMPDIR/openldap-tools"
          printf '#!%s\n' "$CONFIG_SHELL" > "$TMPDIR/openldap-tools/soelim"
          cat >> "$TMPDIR/openldap-tools/soelim" <<'EOF'
          expandSoelim() {
            while IFS= read -r line; do
              case "$line" in
                '.so '*)
                  includePath=''${line#'.so '}
                  expandSoelim < "$includePath"
                  ;;
                *) printf '%s\n' "$line" ;;
              esac
            done
          }

          case "''${1:-}" in
            "" | -) expandSoelim ;;
            *)
              for inputPath in "$@"; do
                expandSoelim < "$inputPath"
              done
              ;;
          esac
          EOF
          chmod +x "$TMPDIR/openldap-tools/soelim"
          PATH="$TMPDIR/openldap-tools:$PATH"
          export PATH
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
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "deployment";
        key = "openldap-test";
        stage = "host";
      };
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      credential = key:
        lib.abilities.resourceReference {
          interface = serviceManagement.interfaces.credentialDelivery.identity;
          resource = {
            provider = credentialProvider;
            inherit key;
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
      evaluate = openldapConfig:
        lib.evalModules {
          inherit lib;
          modules = [
            ../../modules/abilities/default.nix
            {
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
                contributable = true;
              };
              aos.abilities.environment = builtins.removeAttrs environmentId ["_type"];
              openldap = openldapConfig;
            }
          ];
          packageModules = [
            {
              name = "openldap";
              module.imports = [./_openldap/module.nix];
            }
          ];
        };
      valid = evaluate {
        enable = true;
        suffix = "dc=aos,dc=test";
        rootDn = "cn=admin,dc=aos,dc=test";
        rootPassword.resource = credential "root-password";
      };
      tls = evaluate {
        enable = true;
        rootPassword.resource = credential "root-password";
        tls = {
          enable = true;
          certificate.resource = credential "tls-certificate";
          privateKey.resource = credential "tls-private-key";
          trustedCa.resource = credential "tls-ca";
        };
      };
      missingPassword = evaluate {enable = true;};
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      requests = valid.config.aos.abilities.requests;
      tlsRequests = tls.config.aos.abilities.requests;
      configuration = requests."openldap:server-configuration".parameters;
      fragmentKinds = builtins.map (fragment: fragment.kind) configuration.source.fragments;
      modulePathFragments = builtins.filter
        (fragment: fragment.kind == "artifact-directory-path")
        configuration.source.fragments;
      contractHolds =
        assertionsHold valid
        && assertionsHold tls
        && !assertionsHold missingPassword
        && builtins.length (builtins.attrNames requests) == 16
        && builtins.length (builtins.attrNames tlsRequests) == 20
        && builtins.hasAttr "openldap:main-lifecycle" requests
        && !(builtins.hasAttr "openldap:main-credentials" requests)
        && builtins.hasAttr "openldap:main-credentials" tlsRequests
        && builtins.elem "artifact-file-path" fragmentKinds
        && builtins.length modulePathFragments == 1
        && (builtins.head modulePathFragments).reference.path == "libexec/openldap"
        && builtins.elem "credential-content" fragmentKinds
        && configuration.mode == "0600"
        && !(lib.hasInfix "/nix/store/" (builtins.toJSON configuration));
      testConfiguration = builtins.toFile "openldap-test.conf" ''
        include ${self}/etc/openldap/schema/core.schema
        include ${self}/etc/openldap/schema/cosine.schema
        include ${self}/etc/openldap/schema/inetorgperson.schema
        modulepath ${self}/libexec/openldap
        pidfile /tmp/openldap-test/slapd.pid
        argsfile /tmp/openldap-test/slapd.args
        database mdb
        maxsize 1073741824
        suffix "dc=aos,dc=test"
        rootdn "cn=admin,dc=aos,dc=test"
        directory /tmp/openldap-test/data
        index objectClass eq
      '';
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

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "openldap-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the OpenLDAP native ability checks failed";

      config-lifecycle = testing.mkVMTest {
        name = "networking-openldap-config-lifecycle";
        rootfsDeps = [self testConfiguration pkgs.grep pkgs.iproute2];
        testScript = ''
          ${pkgs.iproute2}/sbin/ip link set lo up
          mkdir -p /tmp/openldap-test/data
          cp ${testConfiguration} /tmp/slapd.conf
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
