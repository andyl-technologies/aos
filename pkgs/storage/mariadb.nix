##! MariaDB — Community relational database server
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  bison,
  pkg-config,
  perl,
  python3,
  boost,
  bzip2,
  curl,
  icu,
  jemalloc,
  libaio,
  libevent,
  liburing,
  linux-pam,
  fmt,
  lz4,
  ncurses,
  numactl,
  openssl,
  pcre2,
  rpcsvc-proto,
  snappy,
  systemd,
  xz,
  zlib,
  zstd,
  bash,
  coreutils,
  sed,
  writeShellScriptBin,
}: let
  version = "11.4.12";
  control = writeShellScriptBin "mariadb-control" ''
    set -euo pipefail

    runtime=/etc/aos/packages/mariadb/runtime.env
    config=/etc/aos/packages/mariadb/my.cnf
    bootstrap=/run/mariadb/bootstrap.sql

    enabled() {
      set -a
      source "$runtime"
      set +a
      [[ "''${MARIADB_ENABLED:-0}" == 1 ]]
    }

    case "''${1:-}" in
      enabled)
        enabled
        ;;
      prepare)
        ${coreutils}/bin/install -m 0600 /dev/null "$bootstrap"
        for name in admin-bootstrap-sql replication-bootstrap-sql; do
          source="''${CREDENTIALS_DIRECTORY:-}/$name"
          if [[ -n "''${CREDENTIALS_DIRECTORY:-}" && -r "$source" ]]; then
            ${coreutils}/bin/cat "$source" >> "$bootstrap"
            printf '\n' >> "$bootstrap"
          fi
        done
        ;;
      init)
        if [[ ! -d /var/lib/aos-pkg-mariadb/mysql ]]; then
          /bin/mariadb-install-db \
            --defaults-file="$config" \
            --auth-root-authentication-method=socket \
            --force \
            --skip-test-db
        fi
        ;;
      run)
        exec /bin/mariadbd --defaults-file="$config"
        ;;
      cleanup)
        ${coreutils}/bin/rm -f -- "$bootstrap"
        ;;
      *)
        echo "usage: mariadb-control {enabled|prepare|init|run|cleanup}" >&2
        exit 64
        ;;
    esac
  '';
in
  mkDerivation {
    pname = "mariadb";
    inherit version;

    src = fetchurl {
      urls = [
        "https://archive.mariadb.org/mariadb-${version}/source/mariadb-${version}.tar.gz"
      ];
      hash = "sha256-WreIPbUZv86/3SqsCbxVRKEs4yjznt1G0L8BaQYV72w=";
    };

    buildDeps = [
      gnumake
      cmake
      bison
      pkg-config
      perl
      python3
      boost.dev
      fmt
      rpcsvc-proto
    ];
    runtimeDeps = [
      boost
      bzip2
      curl
      icu
      jemalloc
      libaio
      libevent
      liburing
      linux-pam
      lz4
      ncurses
      numactl
      openssl
      pcre2
      snappy
      systemd
      xz
      zlib
      zstd
      bash
      coreutils
      sed
      control
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mariadb-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DINSTALL_SYSCONFDIR=$out/etc \
            -DINSTALL_SYSCONF2DIR=$out/etc/my.cnf.d \
            -DMYSQL_DATADIR=/var/lib/mysql \
            -DMYSQL_UNIX_ADDR=/run/mysqld/mysqld.sock \
            -DBUILD_CONFIG=mysql_release \
            -DFEATURE_SET=community \
            -DWITH_SSL=system \
            -DWITH_ZLIB=system \
            -DWITH_ZSTD=system \
            -DWITH_PCRE=system \
            -DGRN_WITH_LIBEVENT:STRING=${libevent} \
            -DWITH_JEMALLOC:STRING=yes \
            -DWITH_NUMA:BOOL=ON \
            -DWITH_LIBURING:BOOL=ON \
            -DURING_INCLUDE_DIRS=${liburing}/include \
            -DURING_LIBRARIES=${liburing}/lib/liburing.so \
            -DLIBAIO_INCLUDE_DIRS=${libaio}/include \
            -DLIBAIO_LIBRARIES=${libaio}/lib/libaio.so \
            -DCURSES_INCLUDE_PATH=${ncurses}/include \
            -DCURSES_LIBRARY=${ncurses}/lib/libncursesw.so \
            -DLIBLZMA_INCLUDE_DIR=${xz}/include \
            -DLIBLZMA_LIBRARY=${xz}/lib/liblzma.so \
            -DCMAKE_PREFIX_PATH="${lz4};${snappy};${zstd};${bzip2};${xz};${linux-pam};${fmt}" \
            -DWITH_LIBFMT=system \
            -DLIBFMT_INCLUDE_DIR=${fmt}/include \
            -Dlz4_ROOT_DIR=${lz4} \
            -DWITH_ROCKSDB_BZip2:STRING=ON \
            -DWITH_ROCKSDB_LZ4:STRING=ON \
            -DWITH_ROCKSDB_Snappy:STRING=ON \
            -DWITH_ROCKSDB_ZSTD:STRING=ON \
            -DWITH_SYSTEMD:STRING=yes \
            -DWITH_UNIT_TESTS:BOOL=ON \
            -DPLUGIN_COLUMNSTORE:STRING=NO \
            -DAWS_SDK_EXTERNAL_PROJECT:BOOL=OFF \
            -DBOOST_ROOT=${boost.dev}

          # mysql_release's documented `community` set is upstream's complete
          # GPLv2 community feature set (currently xlarge). The AWS KMS plugin
          # is deliberately outside that distributable set: upstream requires
          # NOT_FOR_DISTRIBUTION because the Apache-2.0 AWS SDK is incompatible
          # with MariaDB's GPLv2-only server. OFF forbids CMake's network-only
          # ExternalProject fallback; it does not reduce the distributable
          # community feature set.
          for setting in \
            'BUILD_CONFIG:.*=mysql_release' \
            'FEATURE_SET:.*=community' \
            'WITH_SSL:.*=system' \
            'WITH_ZLIB:.*=system' \
            'WITH_ZSTD:.*=system' \
            'WITH_PCRE:.*=system' \
            'GRN_WITH_LIBEVENT:STRING=${libevent}' \
            'WITH_JEMALLOC:STRING=yes' \
            'WITH_NUMA:BOOL=ON' \
            'WITH_LIBURING:BOOL=ON' \
            'WITH_ROCKSDB_BZip2:STRING=ON' \
            'WITH_ROCKSDB_LZ4:STRING=ON' \
            'WITH_ROCKSDB_Snappy:STRING=ON' \
            'WITH_ROCKSDB_ZSTD:STRING=ON' \
            'WITH_SYSTEMD:STRING=yes' \
            'WITH_UNIT_TESTS:BOOL=ON' \
            'PLUGIN_COLUMNSTORE:STRING=NO' \
            'AWS_SDK_EXTERNAL_PROJECT:BOOL=OFF'; do
            grep "^$setting$" CMakeCache.txt
          done
          grep '^#define HAVE_SYSTEMD 1$' include/my_config.h
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

          # Prove the requested features reached built artifacts, not merely
          # the CMake cache. MariaRocks vendors its matched RocksDB source but
          # must link every distributable compression provider from AOS
          # packages. The server itself must retain the requested external I/O
          # and NUMA providers; the cache assertions below additionally bind
          # statically consumed jemalloc and Mroonga/libevent configuration.
          test -f "$out/lib/plugin/ha_rocksdb.so"
          readelf -d "$out/lib/plugin/ha_rocksdb.so" > rocksdb-needed.txt
          for library in libbz2 liblz4 libsnappy libzstd; do
            grep "$library" rocksdb-needed.txt
          done
          test -f "$out/lib/plugin/ha_mroonga.so"
          readelf -d "$out/bin/mariadbd" | grep libaio
          readelf -d "$out/bin/mariadbd" | grep libnuma
          readelf -d "$out/bin/mariadbd" | grep liburing

          mkdir -p "$out/share/aos-build-features"
          grep -E \
            '^(BUILD_CONFIG|FEATURE_SET|WITH_SSL|WITH_ZLIB|WITH_ZSTD|WITH_PCRE|GRN_WITH_LIBEVENT|WITH_JEMALLOC|WITH_NUMA|WITH_LIBURING|WITH_ROCKSDB_BZip2|WITH_ROCKSDB_LZ4|WITH_ROCKSDB_Snappy|WITH_ROCKSDB_ZSTD|WITH_SYSTEMD|WITH_UNIT_TESTS|PLUGIN_COLUMNSTORE|AWS_SDK_EXTERNAL_PROJECT):' \
            CMakeCache.txt > "$out/share/aos-build-features/mariadb-cmake-cache.txt"

          # Upstream installs its initialization helper under scripts even
          # though both its systemd unit and operator documentation expose it
          # as a command. Publish it in bin and replace the forbidden host
          # shell shebang with the hermetic AOS bash.
          install -m 0755 "$out/scripts/mariadb-install-db" "$out/bin/mariadb-install-db"
          sed -i '1c#!${bash}/bin/bash' "$out/bin/mariadb-install-db"

          ln -s ${control}/bin/mariadb-control "$out/bin/mariadb-control"
          test -x "$out/bin/mariadb-install-db"
          test -x "$out/bin/mariadb-control"
        '';
      }
    ];

    expose = {
      units = {
        "mariadb-init.service" = {
          description = "Initialize MariaDB state";
          before = ["mariadb.service"];
          serviceConfig = {
            Type = "oneshot";
            User = "mariadb";
            Group = "mariadb";
            EnvironmentFile = "/etc/aos/packages/mariadb/runtime.env";
            ExecCondition = "/bin/mariadb-control enabled";
            ExecStart = "/bin/mariadb-control init";
            StateDirectory = "aos-pkg-mariadb";
            StateDirectoryMode = "0750";
            RuntimeDirectory = "mariadb";
            RuntimeDirectoryMode = "0750";
            RemainAfterExit = true;
            UMask = "0027";
          };
        };

        "mariadb.service" = {
          description = "MariaDB database server";
          after = ["network.target" "mariadb-init.service"];
          requires = ["mariadb-init.service"];
          restartIfChanged = true;
          stopOnRemoval = true;
          serviceConfig = {
            Type = "notify";
            NotifyAccess = "all";
            User = "mariadb";
            Group = "mariadb";
            EnvironmentFile = "/etc/aos/packages/mariadb/runtime.env";
            ExecCondition = "/bin/mariadb-control enabled";
            ExecStartPre = "/bin/mariadb-control prepare";
            ExecStart = "/bin/mariadb-control run";
            ExecStartPost = "/bin/mariadb-control cleanup";
            ExecStopPost = "/bin/mariadb-control cleanup";
            Restart = "on-failure";
            RestartSec = "5s";
            StateDirectory = "aos-pkg-mariadb";
            StateDirectoryMode = "0750";
            RuntimeDirectory = "mariadb";
            RuntimeDirectoryMode = "0750";
            LogsDirectory = "mariadb";
            LogsDirectoryMode = "0750";
            UMask = "0027";
            LimitNOFILE = "65536";
          };
        };
      };

      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/mariadb/runtime.env";
            format = "env";
            required = ["MARIADB_CONFIG_GENERATION" "MARIADB_ENABLED"];
            units = ["mariadb-init.service" "mariadb.service"];
            reload = "restart";
          }
        ];
        credentials =
          builtins.map (name: {
            inherit name;
            source = "/run/credstore/mariadb/${name}";
            units = ["mariadb.service"];
            encrypted = false;
            optional = true;
          }) [
            "tls-certificate"
            "tls-private-key"
            "tls-ca"
            "admin-bootstrap-sql"
            "replication-bootstrap-sql"
          ];
      };

      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/mariadb/my.cnf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-mariadb";
      };
    };

    configModule = {
      src = ./_mariadb-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "mariadb.bindAddress"
        "mariadb.bootstrap.adminSql"
        "mariadb.bootstrap.replicationSql"
        "mariadb.characterSet"
        "mariadb.collation"
        "mariadb.enable"
        "mariadb.maxConnections"
        "mariadb.port"
        "mariadb.skipNameResolve"
        "mariadb.sqlMode"
        "mariadb.tls.ca"
        "mariadb.tls.certificate"
        "mariadb.tls.enable"
        "mariadb.tls.privateKey"
      ];
      ownsRoots = [
        {
          root = "mariadb";
          interfaceAbi = 1;
        }
      ];
      artifacts = {
        etc = ["aos/packages/mariadb/my.cnf"];
        units = [];
        users = ["mariadb"];
        groups = ["mariadb"];
      };
    };

    meta = {
      description = "MariaDB community relational database server";
      homepage = "https://mariadb.org/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      moduleStub = {
        options = {
          assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          mariadb.config = lib.mkOption {
            type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
            default = {};
          };
          mariadb.credentials = lib.mkOption {
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
      };
      evaluate = value:
        lib.evalModules {
          modules = [moduleStub ./_mariadb-config/module.nix {mariadb = value;}];
          inherit lib;
        };
      evaluated = evaluate {
        enable = true;
        bindAddress = "127.0.0.1";
        maxConnections = 200;
        tls = {
          enable = true;
          certificate.ref = "system-credential:mariadb-certificate";
          privateKey.ref = "system-credential:mariadb-private-key";
          ca.ref = "tpm2-credstore:mariadb-ca";
        };
        bootstrap = {
          adminSql.ref = "system-credential:mariadb-admin-bootstrap";
          replicationSql.ref = "desired-toml:mariadb-replication-bootstrap";
        };
      };
      assertionsHold = builtins.all (assertion: assertion.assertion) evaluated.config.assertions;
      rendered = evaluated.config.environment.etc."aos/packages/mariadb/my.cnf".text;
      renderedFile = pkgs.writeTextFile {
        name = "mariadb-config-module-check";
        destination = "/my.cnf";
        text = rendered;
      };
      lifecycleEvaluated = evaluate {
        enable = true;
        bindAddress = "127.0.0.1";
        maxConnections = 200;
      };
      lifecycleRenderedFile = pkgs.writeTextFile {
        name = "mariadb-lifecycle-config";
        destination = "/my.cnf";
        text = lifecycleEvaluated.config.environment.etc."aos/packages/mariadb/my.cnf".text;
      };
      invalidTls = evaluate {
        enable = true;
        tls = {
          enable = true;
          certificate.ref = "system-credential:mariadb-certificate";
        };
      };
      invalidTlsRejected = !builtins.all (assertion: assertion.assertion) invalidTls.config.assertions;
    in {
      version = testing.mkToolCheck {
        pname = "storage-mariadb";
        tool = self;
        command = "mariadbd --no-defaults --version";
      };

      features = testing.mkVMTest {
        name = "storage-mariadb-features";
        rootfsDeps = [self pkgs.grep];
        testScript = ''
          features=${self}/share/aos-build-features/mariadb-cmake-cache.txt
          grep '^BUILD_CONFIG:.*=mysql_release$' "$features"
          grep '^FEATURE_SET:.*=community$' "$features"
          grep '^WITH_SSL:.*=system$' "$features"
          grep '^WITH_ZLIB:.*=system$' "$features"
          grep '^WITH_ZSTD:.*=system$' "$features"
          grep '^WITH_PCRE:.*=system$' "$features"
          grep '^GRN_WITH_LIBEVENT:STRING=${libevent}$' "$features"
          grep '^WITH_JEMALLOC:STRING=yes$' "$features"
          grep '^WITH_NUMA:BOOL=ON$' "$features"
          grep '^WITH_LIBURING:BOOL=ON$' "$features"
          grep '^WITH_ROCKSDB_BZip2:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_LZ4:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_Snappy:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_ZSTD:STRING=ON$' "$features"
          grep '^WITH_SYSTEMD:STRING=yes$' "$features"
          grep '^WITH_UNIT_TESTS:BOOL=ON$' "$features"
          grep '^PLUGIN_COLUMNSTORE:STRING=NO$' "$features"
          grep '^AWS_SDK_EXTERNAL_PROJECT:BOOL=OFF$' "$features"
        '';
      };

      config-module-contract = assert assertionsHold;
      assert invalidTlsRejected;
      assert evaluated.config.mariadb.config.runtime.MARIADB_ENABLED == "1";
      assert builtins.stringLength evaluated.config.mariadb.config.runtime.MARIADB_CONFIG_GENERATION == 64;
      assert evaluated.config.mariadb.credentials."tls-certificate".ref == "system-credential:mariadb-certificate";
        pkgs.runCommand "storage-mariadb-config-module-contract" {} ''
            test -f ${self.config}/module.nix
            test -f ${self.config}/config-meta.json
            grep -q '"root":"mariadb"' ${self.config}/config-meta.json
            grep -q 'aos/packages/mariadb/my.cnf' ${self.config}/config-meta.json

          grep -q '^bind-address=127.0.0.1$' ${renderedFile}/my.cnf
          grep -q '^max-connections=200$' ${renderedFile}/my.cnf
          grep -q '^ssl-cert=/run/credentials/mariadb.service/tls-certificate$' ${renderedFile}/my.cnf
          ${self}/bin/my_print_defaults --defaults-file=${renderedFile}/my.cnf mariadbd \
            | grep -q -- '--max-connections=200'

          for name in tls-certificate tls-private-key tls-ca admin-bootstrap-sql replication-bootstrap-sql; do
            grep -q "\"encrypted\":false,\"name\":\"$name\",\"optional\":true,\"source\":\"/run/credstore/mariadb/$name\",\"units\":\[\"mariadb.service\"\]" \
                ${self.expose}/manifest.json
            done
            if grep -Eq 'LoadCredential(Encrypted)?=.*(tls-|bootstrap-sql)' ${self.expose}/units/mariadb.service; then
            echo "optional MariaDB credentials became unconditional unit bindings" >&2
            exit 1
          fi
            grep -qx 'User=mariadb' ${self.expose}/units/mariadb.service
            grep -Eq '^Requires=.*mariadb-init\.service( |$)' ${self.expose}/units/mariadb.service
            grep -Eq '^After=.*mariadb-init\.service( |$)' ${self.expose}/units/mariadb.service
            grep -Eq '^After=.*network\.target( |$)' ${self.expose}/units/mariadb.service
            grep -qx 'StateDirectory=aos-pkg-mariadb' ${self.expose}/units/mariadb.service
            grep -qx 'BindReadOnlyPaths=/etc/aos/packages/mariadb/my.cnf' ${self.expose}/units/mariadb.service

          printf '[mariadbd]\nunknown-aos-option=1\n' > malformed.cnf
          if ${self}/bin/mariadbd --defaults-file="$PWD/malformed.cnf" --verbose --help >/dev/null 2>&1; then
            echo "MariaDB accepted an unknown generated option" >&2
            exit 1
          fi

          mkdir -p "$out"
          printf '%s\n' PASS > "$out/result"
        '';

      config-module-lifecycle = import ./_mariadb-tests/lifecycle.nix {
        inherit testing self;
        renderedFile = lifecycleRenderedFile;
        coreutils = pkgs.coreutils;
        grep = pkgs.grep;
        iproute2 = pkgs.iproute2;
        sed = pkgs.sed;
      };
    };
  }
