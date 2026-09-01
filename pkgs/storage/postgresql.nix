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
  tar,
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
  openpam,
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
  stdenv,
  buildPackages,
  darwin-sdk,
}: let
  version = "18.4";
  isDarwin = stdenv.hostPlatform.isDarwin;
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

    buildDeps =
      if isDarwin
      then [
        docbook-xml
        docbook-xsl
      ]
      else [
        gnumake
        pkg-config
        bison
        flex
        perl
        python3
        llvm
        clangForBitcode
        tcl
        docbook-xml
        docbook-xsl
        gettext
        libxml2
        libxslt
        util-linux
      ];
    runtimeDeps =
      if isDarwin
      then [
        bison
        flex
        coreutils
        pkg-config
        tar
        curl
        gettext
        icu
        krb5
        libxml2
        libxslt
        openpam
        llvm
        lz4
        openldap
        openssl
        perl
        python3
        readline
        tcl
        tzdata
        zlib
        zstd
      ]
      else
        [
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
        ]
        ++ [bash coreutils control];
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
        script =
          if isDarwin
          then ''
            # Build drivers must execute on Linux without adding their native
            # headers, libraries, or pkg-config files to the target search
            # environment. Reference only their executables here; target
            # counterparts remain runtime dependencies for installed PGXS.
            export BISON=${buildPackages.bison}/bin/bison
            export FLEX=${buildPackages.flex}/bin/flex
            export MSGFMT=${buildPackages.gettext}/bin/msgfmt
            export MSGMERGE=${buildPackages.gettext}/bin/msgmerge
            export PKG_CONFIG=${buildPackages.pkg-config}/bin/pkg-config
            export XGETTEXT=${buildPackages.gettext}/bin/xgettext
            export XMLLINT=${buildPackages.libxml2}/bin/xmllint
            export XSLTPROC=${buildPackages.libxslt}/bin/xsltproc

            # PostgreSQL needs native LLVM utilities to generate bitcode, but
            # must compile and link against the Darwin LLVM headers and dylib.
            mkdir -p .aos-native-tools
            cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
            case "$1" in
              --bindir)
                printf '%s\n' '${buildPackages.llvm}/bin'
                ;;
              *)
                '${buildPackages.llvm}/bin/llvm-config' "$@" |
                  sed 's|${buildPackages.llvm}|${llvm}|g'
                ;;
            esac
            LLVM_CONFIG_WRAPPER
            chmod +x .aos-native-tools/llvm-config
            export LLVM_CONFIG=$PWD/.aos-native-tools/llvm-config
            export CLANG="${buildPackages.llvm}/bin/clang --target=${stdenv.hostPlatform.config} --sysroot=${stdenv.sdk}"
            export TCLSH=${buildPackages.tcl}/bin/tclsh9.0

            # Query the Darwin Perl configuration using the native interpreter.
            # Config.pm is pure Perl and the versions are identical across the
            # build and host package sets, so no target executable is run.
            # Net/Config.pm has the same basename and may sort before the
            # architecture configuration on x86_64. Select the latter
            # explicitly so configure sees useshrplib and libperl.dylib.
            target_perl_config=$(find ${perl.dev}/lib \
              -name Config.pm ! -path '*/Net/Config.pm' -print -quit)
            test -n "$target_perl_config"
            target_perl_archlib=$(dirname "$target_perl_config")
            target_perl_privlib=$(dirname "$target_perl_archlib")
            export PERL=${buildPackages.perl}/bin/perl
            export PERL5LIB="$target_perl_archlib:$target_perl_privlib"

            # Only PostgreSQL's small sysconfig queries need target Python
            # answers. The wrapper delegates every other operation to the
            # native interpreter used for source generation.
            cat > .aos-native-tools/python3 <<'PYTHON_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
            if [ "$1" = -c ]; then
              case "$2" in
                *"get_config_vars('LIBPL')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_var('INCLUDEPY')"*)
                  printf '%s\n' '-I${python3}/include/python3.14'
                  exit 0
                  ;;
                *"get_config_vars('LIBDIR')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_vars('LDLIBRARY')"*)
                  printf '%s\n' 'libpython3.14.dylib'
                  exit 0
                  ;;
                *"get_config_vars('LIBS','LIBC','LIBM','BASEMODLIBS')"*)
                  printf '\n'
                  exit 0
                  ;;
              esac
            fi
            exec '${buildPackages.python3}/bin/python3' "$@"
            PYTHON_CONFIG_WRAPPER
            chmod +x .aos-native-tools/python3
            export PYTHON=$PWD/.aos-native-tools/python3

            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-nls \
              --with-llvm \
              --with-icu \
              --with-tcl \
              --with-tclconfig=${tcl}/lib \
              --with-gssapi \
              --with-ldap \
              --with-system-tzdata=${tzdata}/share/zoneinfo \
              --with-perl \
              --with-python \
              --with-pam \
              --with-uuid=e2fs \
              --with-libcurl \
              --with-libxml \
              --with-libxslt \
              --with-lz4 \
              --with-zstd \
              --with-ssl=openssl

            # CONFIGURE_ARGS is compiled into pg_config and the server, and
            # the generated header is also installed for extensions. Keep the
            # native wrappers active in the build makefiles, but publish only
            # the corresponding Darwin-side tool paths in that metadata.
            sed -i \
              -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
              -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
              -e "s|CC=$CC|CC=${llvm}/bin/clang|g" \
              -e "s|CXX=$CXX|CXX=${llvm}/bin/clang++|g" \
              -e 's|${buildPackages.llvm}|${llvm}|g' \
              -e 's|${buildPackages.gettext}|${gettext}|g' \
              -e 's|${buildPackages.pkg-config}|${pkg-config}|g' \
              -e 's|${buildPackages.perl}|${perl}|g' \
              -e 's|${buildPackages.python3}|${python3}|g' \
              -e 's|${buildPackages.tcl}|${tcl}|g' \
              -e "s|${stdenv.sdk}|$out/share/darwin-sdk|g" \
              -e "s| 'PKG_CONFIG_PATH=[^']*'||g" \
              src/include/pg_config.h

            for macro in \
              ENABLE_GSS ENABLE_NLS USE_ICU USE_LDAP USE_LLVM USE_LIBCURL \
              USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM USE_ZSTD \
              HAVE_UUID_E2FS; do
              grep "^#define $macro 1$" src/include/pg_config.h
            done

            # pg_config and installed PGXS makefiles must name a compiler that
            # runs on Darwin, not the Linux-hosted cross wrapper used here.
            sed -i '/#include "common\/config_info.h"/a\
            #undef VAL_CC\
            #define VAL_CC "${llvm}/bin/clang"' \
              src/common/config_info.c
          ''
          else ''
            export LLVM_CONFIG=${llvm}/bin/llvm-config
            # PostgreSQL invokes Clang directly for LLVM bitcode, so retain
            # the libc header path normally injected by the AOS GCC wrapper.
            export CLANG="${llvm}/bin/clang -idirafter ${stdenv.cc.libc.dev}/include"
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
        script =
          if isDarwin
          then ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ${buildPackages.gnumake}/bin/make -j$NIX_BUILD_CORES world
          ''
          else ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            make -j$NIX_BUILD_CORES world
          '';
      }
      {
        name = "install";
        script =
          (
            if isDarwin
            then ''
              export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
              ${buildPackages.gnumake}/bin/make install-world
              test -f "$out/share/doc/html/index.html"
              test -f "$out/share/man/man1/postgres.1"
              test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"

              # Installed PGXS can compile extensions with LLVM on Darwin, but
              # must not retain the Linux-hosted compiler SDK used by this cross
              # build. Publish the clean target SDK beside PostgreSQL and point
              # only installed metadata at that self-contained copy.
              mkdir -p "$out/share/darwin-sdk/share"
              cp -R \
                ${darwin-sdk}/SDKSettings.json \
                ${darwin-sdk}/System \
                ${darwin-sdk}/usr \
                "$out/share/darwin-sdk/"
              cp -R ${darwin-sdk}/share/licenses "$out/share/darwin-sdk/share/"

              # PGXS is target-side tooling. Retarget interpreter and LLVM
              # paths recorded while Linux-native generators built the tree.
              find "$out/lib/pgxs" -type f -exec sed -i \
                -e 's|${buildPackages.perl}|${perl}|g' \
                -e 's|${buildPackages.python3}|${python3}|g' \
                -e 's|${buildPackages.llvm}|${llvm}|g' \
                -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
                -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
                -e "s|${stdenv.sdk}|$out/share/darwin-sdk|g" \
                -e "s|$CC|${llvm}/bin/clang|g" \
                -e "s|^CXX = .*|CXX = ${llvm}/bin/clang++|" \
                -e "s|^AR = .*|AR = ${llvm}/bin/llvm-ar|" \
                -e "s|^BISON = .*|BISON = ${bison}/bin/bison|" \
                -e "s|^FLEX = .*|FLEX = ${flex}/bin/flex|" \
                -e "s|^MSGFMT  = .*|MSGFMT  = ${gettext}/bin/msgfmt|" \
                -e "s|^MSGMERGE = .*|MSGMERGE = ${gettext}/bin/msgmerge|" \
                -e "s|^PKG_CONFIG[[:space:]]*= .*|PKG_CONFIG = ${pkg-config}/bin/pkg-config|" \
                -e "s|^TAR[[:space:]]*= .*|TAR = ${tar}/bin/tar|" \
                -e "s|^TCLSH[[:space:]]*= .*|TCLSH = ${tcl}/bin/tclsh9.0|" \
                -e "s|^XGETTEXT = .*|XGETTEXT = ${gettext}/bin/xgettext|" \
                -e "s|^install_bin = .*|install_bin = ${coreutils}/bin/install -c|" \
                -e "s|^MKDIR_P = .*|MKDIR_P = ${coreutils}/bin/mkdir -p|" \
                -e "s|^STRIP[[:space:]]*= .*|STRIP = ${llvm}/bin/llvm-strip|" \
                -e "s|^STRIP_STATIC_LIB = .*|STRIP_STATIC_LIB = ${llvm}/bin/llvm-strip -S|" \
                -e "s|^STRIP_SHARED_LIB = .*|STRIP_SHARED_LIB = ${llvm}/bin/llvm-strip -S|" \
                -e "s|^XMLLINT[[:space:]]*= .*|XMLLINT = ${libxml2}/bin/xmllint|" \
                -e "s|^XSLTPROC[[:space:]]*= .*|XSLTPROC = ${libxslt}/bin/xsltproc|" \
                -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
                -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
                {} +
            ''
            else ''
              export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
              make install-world
              test -f "$out/share/doc/html/index.html"
              test -f "$out/share/man/man1/postgres.1"
              test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"
              sed -i \
                -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
                -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
                "$out/lib/pgxs/src/Makefile.global"
            ''
          )
          + ''
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
          test -f ${self}/share/doc/html/index.html
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
