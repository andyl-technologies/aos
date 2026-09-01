##! PostgreSQL — Object-relational database server
{
  lib,
  mkDerivation,
  writeShellScriptBin,
  fetchurl,
  gnumake,
  bash,
  coreutils,
  pkg-config,
  bison,
  flex,
  perl,
  python3,
  llvm,
  glibc,
  linux-headers,
  curl,
  docbook-xml,
  docbook-xsl,
  gettext,
  icu,
  krb5,
  libselinux,
  liburing,
  libxml2,
  libxslt,
  linux-pam,
  lz4,
  numactl,
  openldap,
  openssl,
  readline,
  systemd,
  tcl,
  tzdata,
  util-linux,
  zlib,
  zstd,
}: let
  version = "18.4";
  control = writeShellScriptBin "postgresql-control" ''
    set -euo pipefail

    service_env=/etc/aos/packages/postgresql/service.env
    data_directory=/var/lib/aos-pkg-postgresql/data
    staging_directory=/var/lib/aos-pkg-postgresql/.data-initializing
    server_config=/etc/postgresql/postgresql.conf
    credential_directory="''${CREDENTIALS_DIRECTORY:-/run/credentials/postgresql.service}"

    load_environment() {
      # The env artifact is authenticated and rendered by AOS. Do not accept
      # process-environment overrides for lifecycle policy.
      unset \
        POSTGRESQL_ENABLED POSTGRESQL_STANDBY POSTGRESQL_SUPERUSER \
        POSTGRESQL_PRIMARY_HOST POSTGRESQL_PRIMARY_PORT \
        POSTGRESQL_REPLICATION_USER POSTGRESQL_REPLICATION_SLOT
      source "$service_env"
    }

    running() {
      /bin/pg_ctl status -D "$data_directory" >/dev/null 2>&1
    }

    case "''${1:-}" in
      enabled)
        load_environment
        [[ "$POSTGRESQL_ENABLED" == true ]]
        ;;
      prepare)
        load_environment

        if [[ -L "$data_directory" ]]; then
          echo "PostgreSQL data directory must not be a symbolic link" >&2
          exit 78
        fi

        if [[ ! -s "$data_directory/PG_VERSION" ]]; then
          if [[ -e "$data_directory" || -L "$data_directory" ]]; then
            if [[ -d "$data_directory" && ! -L "$data_directory" ]] \
              && [[ -z "$(${coreutils}/bin/ls -A "$data_directory")" ]]; then
              ${coreutils}/bin/rmdir "$data_directory"
            else
              echo "PostgreSQL data directory exists without PG_VERSION; refusing to overwrite it" >&2
              exit 78
            fi
          fi

          # This exact service-owned sibling contains no accepted database
          # state. A prior interrupted attempt can be retried safely, while
          # the final data directory is never recursively removed.
          ${coreutils}/bin/rm -rf "$staging_directory"
          ${coreutils}/bin/mkdir -m 0700 "$staging_directory"

          if [[ "$POSTGRESQL_STANDBY" == true ]]; then
            passfile="$credential_directory/replication-passfile"
            if [[ ! -r "$passfile" ]]; then
              echo "PostgreSQL standby initialization requires replication-passfile" >&2
              exit 78
            fi
            slot_args=()
            if [[ -n "''${POSTGRESQL_REPLICATION_SLOT:-}" ]]; then
              slot_args+=(--slot="$POSTGRESQL_REPLICATION_SLOT")
            fi
            PGPASSFILE="$passfile" /bin/pg_basebackup \
              --pgdata="$staging_directory" \
              --host="$POSTGRESQL_PRIMARY_HOST" \
              --port="$POSTGRESQL_PRIMARY_PORT" \
              --username="$POSTGRESQL_REPLICATION_USER" \
              --wal-method=stream \
              --checkpoint=fast \
              --no-password \
              "''${slot_args[@]}"
          else
            password_file="$credential_directory/bootstrap-superuser-password"
            if [[ ! -r "$password_file" ]]; then
              echo "PostgreSQL initialization requires bootstrap-superuser-password" >&2
              exit 78
            fi
            /bin/initdb \
              --pgdata="$staging_directory" \
              --username="$POSTGRESQL_SUPERUSER" \
              --pwfile="$password_file" \
              --auth-local=peer \
              --auth-host=scram-sha-256 \
              --encoding=UTF8 \
              --locale=C
          fi

          if [[ ! -s "$staging_directory/PG_VERSION" ]]; then
            echo "PostgreSQL initialization completed without PG_VERSION" >&2
            exit 78
          fi
          ${coreutils}/bin/mv "$staging_directory" "$data_directory"
        fi

        if [[ "$POSTGRESQL_STANDBY" == true ]]; then
          ${coreutils}/bin/touch "$data_directory/standby.signal"
        else
          ${coreutils}/bin/rm -f "$data_directory/standby.signal"
        fi

        # -C processes the complete postgresql.conf and rejects malformed or
        # unknown parameters without starting a second postmaster.
        /bin/postgres -D "$data_directory" -C port -c config_file="$server_config" >/dev/null
        ;;
      reload)
        load_environment
        if [[ "$POSTGRESQL_ENABLED" == true ]]; then
          /bin/postgres -D "$data_directory" -C port -c config_file="$server_config" >/dev/null
          /bin/pg_ctl reload -D "$data_directory"
        elif running; then
          /bin/pg_ctl stop -D "$data_directory" -m fast -w
        fi
        ;;
      stop)
        if running; then
          /bin/pg_ctl stop -D "$data_directory" -m fast -w
        fi
        ;;
      *)
        echo "usage: postgresql-control {enabled|prepare|reload|stop}" >&2
        exit 64
        ;;
    esac
  '';
  clangForBitcode = writeShellScriptBin "clang" ''
    exec ${llvm}/bin/clang \
      -isystem ${glibc.dev}/include \
      -isystem ${linux-headers}/include \
      "$@"
  '';
in
  mkDerivation {
    pname = "postgresql";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.postgresql.org/pub/source/v${version}/postgresql-${version}.tar.bz2"
      ];
      hash = "sha256-gagexpX7DHkBQH3vqh0veXNhcVTPJ7p046erjmRDYJQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
      bison
      flex
      perl
      python3
      llvm
      clangForBitcode
      docbook-xml
      docbook-xsl
      gettext
      libxml2
      libxslt
      tcl
      util-linux
    ];
    runtimeDeps = [
      bash
      control
      coreutils
      curl
      icu
      krb5
      libselinux
      liburing
      libxml2
      libxslt
      linux-pam
      llvm
      lz4
      numactl
      openldap
      openssl
      perl
      python3
      readline
      systemd
      tcl
      tzdata
      util-linux
      zlib
      zstd
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd postgresql-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export LLVM_CONFIG=${llvm}/bin/llvm-config
          export CLANG=${clangForBitcode}/bin/clang
          export TCLSH=${tcl}/bin/tclsh9.0
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          ./configure \
            --prefix=$out \
            --enable-nls \
            --with-llvm \
            --with-icu \
            --with-tcl \
            --with-tclconfig=${tcl}/lib \
            --with-gssapi \
            --with-ldap \
            --with-liburing \
            --with-libnuma \
            --with-system-tzdata=${tzdata}/share/zoneinfo \
            --with-perl \
            --with-python \
            --with-pam \
            --with-selinux \
            --with-systemd \
            --with-uuid=e2fs \
            --with-libcurl \
            --with-libxml \
            --with-libxslt \
            --with-lz4 \
            --with-zstd \
            --with-ssl=openssl

          for macro in \
            ENABLE_GSS ENABLE_NLS HAVE_LIBNUMA USE_ICU USE_LDAP USE_LIBURING USE_LLVM \
            USE_LIBCURL USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM \
            USE_SYSTEMD USE_ZSTD HAVE_LIBSELINUX HAVE_UUID_E2FS; do
            grep "^#define $macro 1$" src/include/pg_config.h
          done
        '';
      }
      {
        name = "build";
        script = ''
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          make -j$NIX_BUILD_CORES world
        '';
      }
      {
        name = "install";
        script = ''
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          make install-world
          test -f "$out/share/doc/html/index.html"
          test -f "$out/share/man/man1/postgres.1"
          test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"
          ln -s ${control}/bin/postgresql-control "$out/bin/postgresql-control"
        '';
      }
    ];

    expose = {
      units."postgresql-init.service" = {
        description = "Initialize PostgreSQL database state";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        before = ["postgresql.service"];
        restartIfChanged = true;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          DynamicUser = true;
          StateDirectory = "aos-pkg-postgresql";
          StateDirectoryMode = "0700";
          # The package-wide Landlock policy includes the server socket path;
          # create it for the init unit as well so policy setup is fail-closed
          # rather than depending on the later server unit to create it.
          RuntimeDirectory = "postgresql";
          RuntimeDirectoryMode = "0755";
          UMask = "0077";
          EnvironmentFile = "/etc/aos/packages/postgresql/service.env";
          ExecCondition = "/bin/postgresql-control enabled";
          ExecStart = "/bin/postgresql-control prepare";
        };
      };

      units."postgresql.service" = {
        description = "PostgreSQL database server";
        after = ["network-online.target" "postgresql-init.service"];
        wants = ["network-online.target"];
        requires = ["postgresql-init.service"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "notify";
          DynamicUser = true;
          RuntimeDirectory = "postgresql";
          # The socket itself is authenticated by pg_hba.conf; traverse access
          # lets non-service users reach the default local Unix socket.
          RuntimeDirectoryMode = "0755";
          StateDirectory = "aos-pkg-postgresql";
          StateDirectoryMode = "0700";
          UMask = "0077";
          EnvironmentFile = "/etc/aos/packages/postgresql/service.env";
          ExecCondition = "/bin/postgresql-control enabled";
          ExecStart = "/bin/postgres -D /var/lib/aos-pkg-postgresql/data -c config_file=/etc/postgresql/postgresql.conf";
          ExecReload = "/bin/postgresql-control reload";
          ExecStop = "/bin/postgresql-control stop";
          KillSignal = "SIGINT";
          TimeoutStopSec = "90s";
          Restart = "on-failure";
          RestartSec = "2s";
          LimitNOFILE = "1048576";
        };
      };

      config = {
        artifacts = [
          {
            name = "service";
            path = "/etc/aos/packages/postgresql/service.env";
            format = "env";
            required = [
              "POSTGRESQL_CONFIG_GENERATION"
              "POSTGRESQL_ENABLED"
              "POSTGRESQL_STANDBY"
              "POSTGRESQL_SUPERUSER"
            ];
            optional = [
              "POSTGRESQL_PRIMARY_HOST"
              "POSTGRESQL_PRIMARY_PORT"
              "POSTGRESQL_REPLICATION_SLOT"
              "POSTGRESQL_REPLICATION_USER"
            ];
            units = ["postgresql-init.service" "postgresql.service"];
            # PostgreSQL accepts reload for only a subset of settings. Treat
            # an arbitrary typed generation change conservatively as restart.
            reload = "restart";
          }
        ];
        credentials =
          builtins.map (credential: {
            inherit (credential) name units;
            source = "/run/credstore/postgresql/${credential.name}";
            encrypted = false;
            optional = true;
          }) [
            {
              name = "bootstrap-superuser-password";
              units = ["postgresql-init.service"];
            }
            {
              name = "replication-passfile";
              units = ["postgresql-init.service" "postgresql.service"];
            }
            {
              name = "tls-ca";
              units = ["postgresql.service"];
            }
            {
              name = "tls-certificate";
              units = ["postgresql.service"];
            }
            {
              name = "tls-private-key";
              units = ["postgresql.service"];
            }
          ];
      };

      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/postgresql/postgresql.conf";
            mode = "read-only";
          }
          {
            path = "/etc/postgresql/pg_hba.conf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-postgresql";
      };
    };

    configModule = {
      src = ./_postgresql-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "postgresql.authentication.rules"
        "postgresql.bootstrap.password"
        "postgresql.bootstrap.superuser"
        "postgresql.clusterName"
        "postgresql.enable"
        "postgresql.listen.addresses"
        "postgresql.listen.port"
        "postgresql.renderedConfig"
        "postgresql.replication.applicationName"
        "postgresql.replication.hotStandby"
        "postgresql.replication.maxReplicationSlots"
        "postgresql.replication.maxWalSenders"
        "postgresql.replication.passfile"
        "postgresql.replication.primary"
        "postgresql.replication.slot"
        "postgresql.replication.user"
        "postgresql.replication.walLevel"
        "postgresql.resources.maintenanceWorkMem"
        "postgresql.resources.maxConnections"
        "postgresql.resources.sharedBuffers"
        "postgresql.resources.workMem"
        "postgresql.settings"
        "postgresql.tls.ca"
        "postgresql.tls.certificate"
        "postgresql.tls.enable"
        "postgresql.tls.minimumProtocol"
        "postgresql.tls.privateKey"
        "postgresql.topology"
      ];
      ownsRoots = [
        {
          root = "postgresql";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = [
          "postgresql/pg_hba.conf"
          "postgresql/postgresql.conf"
        ];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "PostgreSQL object-relational database server";
        sections = {
          lifecycle = lib.aosDoc.section "Initialization and lifecycle" [
            (lib.aosDoc.paragraph "The database cluster is initialized once in durable package state. Desired changes conservatively restart the server because not every PostgreSQL parameter is safely reloadable.")
          ];
          authentication = lib.aosDoc.section "Authentication and TLS" [
            (lib.aosDoc.paragraph "Host authentication rules are ordered and typed. Bootstrap, replication, certificate, private-key, and CA values use opaque credential references and never enter generated files.")
          ];
          settings = lib.aosDoc.section "Additional settings" [
            (lib.aosDoc.paragraph "postgresql.settings is reserved for non-secret parameters without a dedicated option. Dedicated or credential-bearing settings cannot be overridden through that map.")
          ];
        };
      };
    };

    meta = {
      description = "PostgreSQL object-relational database server";
      homepage = "https://www.postgresql.org/";
      license = "PostgreSQL";
    };

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: {
      version = testing.mkToolCheck {
        pname = "storage-postgresql";
        tool = self;
        command = "postgres --version";
      };

      features = testing.mkVMTest {
        name = "storage-postgresql-features";
        rootfsDeps = [self];
        testScript = ''
          pg_config --configure > /tmp/postgresql-configure
          for flag in \
            --enable-nls --with-llvm --with-icu --with-tcl --with-tclconfig=${tcl}/lib \
            --with-gssapi --with-ldap --with-liburing --with-libnuma \
            --with-system-tzdata=${tzdata}/share/zoneinfo \
            --with-perl --with-python --with-pam \
            --with-selinux --with-systemd --with-uuid=e2fs --with-libcurl \
            --with-libxml --with-libxslt --with-lz4 --with-zstd \
            --with-ssl=openssl; do
            grep -- "$flag" /tmp/postgresql-configure
          done
          test -f ${self}/share/doc/postgresql/html/index.html
          test -f ${self}/share/man/man1/postgres.1
          test -n "$(find ${self}/share/locale -name '*.mo' -print -quit)"
        '';
      };

      runtime-contract = import ./_postgresql-tests/lifecycle.nix {
        inherit testing self;
        inherit (pkgs) coreutils grep sed;
      };

      module-contract = import ./_postgresql-tests/module.nix {
        inherit lib pkgs;
        module = ./_postgresql-config/module.nix;
      };

      expose-contract = import ./_postgresql-tests/expose.nix {
        inherit pkgs self;
      };
    };
  }
