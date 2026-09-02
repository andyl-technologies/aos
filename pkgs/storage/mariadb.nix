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
  fmt,
  icu,
  jemalloc,
  libaio,
  libevent,
  liburing,
  linux-pam,
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
  openpam,
  stdenv,
  buildPackages,
  bash,
  coreutils,
  sed,
  writeShellScriptBin,
}: let
  version = "11.4.12";
  isDarwin = stdenv.hostPlatform.isDarwin;
  source = fetchurl {
    urls = [
      "https://archive.mariadb.org/mariadb-${version}/source/mariadb-${version}.tar.gz"
    ];
    hash = "sha256-WreIPbUZv86/3SqsCbxVRKEs4yjznt1G0L8BaQYV72w=";
  };
  messagePackVersion = "2.1.1";
  messagePack = mkDerivation {
    pname = "msgpack-c";
    version = messagePackVersion;
    src = fetchurl {
      urls = [
        "https://github.com/msgpack/msgpack-c/archive/refs/tags/cpp-${messagePackVersion}.tar.gz"
      ];
      hash = "sha256-1r7xLZWYFqOcemly8/FsByTkx/8JJ+tZo1JH3IJntgk=";
    };

    buildDeps =
      if stdenv.isCross
      then [buildPackages.cmake]
      else [cmake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd msgpack-c-cpp-${messagePackVersion}

          # This transition deliberately advances into the generic state
          # handler. Make that intent explicit for AOS's -Werror build.
          sed -i '/^            default:$/i\\            /* fall through */' \
            include/msgpack/unpack_template.h
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DMSGPACK_ENABLE_CXX=OFF \
            -DMSGPACK_BUILD_EXAMPLES=OFF \
            -DMSGPACK_BUILD_TESTS=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
        '';
      }
    ];

    meta = {
      description = "MessagePack C serialization library";
      homepage = "https://msgpack.org/";
      license = "BSL-1.0";
    };
  };

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

  # MariaDB exports six build-time generators for cross builds. Build that
  # small target with the native package set and import it into the Darwin
  # CMake graph so no Mach-O executable is ever run on Linux.
  nativeGenerators =
    if !isDarwin
    then null
    else
      buildPackages.mkDerivation {
        pname = "mariadb-build-generators";
        inherit version;
        src = source;

        buildDeps = [
          buildPackages.gnumake
          buildPackages.cmake
          buildPackages.bison
          buildPackages.pkg-config
          buildPackages.perl
          buildPackages.python3
          buildPackages.ncurses
          buildPackages.openssl
        ];
        runtimeDeps = [buildPackages.fmt];
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
              cmake -S . -B build \
                -DCMAKE_INSTALL_PREFIX=$out \
                -DCMAKE_C_FLAGS="-ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=." \
                -DCMAKE_CXX_FLAGS="-ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=." \
                -DBUILD_CONFIG=mysql_release \
                -DFEATURE_SET=small \
                -DWITH_SSL=system \
                -DOPENSSL_ROOT_DIR=${buildPackages.openssl} \
                -DWITH_ZLIB=bundled \
                -DWITH_PCRE=bundled \
                -DWITH_LIBFMT=system \
                -DHAVE_SYSTEM_LIBFMT:BOOL=ON \
                -DLIBFMT_INCLUDE_DIR=${buildPackages.fmt}/include \
                -DLibfmt_core_h=${buildPackages.fmt}/include/fmt/core.h \
                -DCURSES_LIBRARY=${buildPackages.ncurses}/lib/libncursesw.so \
                -DCURSES_INCLUDE_PATH=${buildPackages.ncurses}/include \
                -DWITH_JEMALLOC:STRING=no \
                -DWITH_NUMA:BOOL=OFF \
                -DIGNORE_AIO_CHECK:BOOL=ON \
                -DWITH_SYSTEMD:STRING=no \
                -DWITH_UNIT_TESTS:BOOL=OFF \
                -DPLUGIN_AUTH_PAM:STRING=NO \
                -DAWS_SDK_EXTERNAL_PROJECT:BOOL=OFF
            '';
          }
          {
            name = "build";
            script = ''
              cmake --build build --parallel $NIX_BUILD_CORES \
                --target import_executables
            '';
          }
          {
            name = "install";
            script = ''
              cp build/import_executables.cmake import_executables.cmake
              mkdir -p "$out/bin"
              for generator in \
                comp_err comp_sql factorial uca-dump gen_lex_hash gen_lex_token; do
                generator_path=$(find build -type f -name "$generator" -perm -u+x -print -quit)
                test -n "$generator_path"
                cp "$generator_path" "$out/bin/$generator"
                sed -i \
                  "s|^  IMPORTED_LOCATION_RELWITHDEBINFO \".*/$generator\"$|  IMPORTED_LOCATION_RELWITHDEBINFO \"$out/bin/$generator\"|" \
                  import_executables.cmake
              done
              cp import_executables.cmake "$out/import_executables.cmake"
            '';
          }
        ];
      };
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
      enabled) enabled ;;
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
          /bin/mariadb-install-db --defaults-file="$config" \
            --auth-root-authentication-method=socket --force --skip-test-db
        fi
        ;;
      run) exec /bin/mariadbd --defaults-file="$config" ;;
      cleanup) ${coreutils}/bin/rm -f -- "$bootstrap" ;;
      *) echo "usage: mariadb-control {enabled|prepare|init|run|cleanup}" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "mariadb";
    inherit version;

    src = source;

    buildDeps =
      if isDarwin
      then [
        buildPackages.gnumake
        buildPackages.cmake
        buildPackages.bison
        buildPackages.pkg-config
        buildPackages.perl
        buildPackages.python3
        buildPackages.rpcsvc-proto
      ]
      else [
        gnumake
        cmake
        bison
        pkg-config
        perl
        python3
        boost.dev
        rpcsvc-proto
      ];
    runtimeDeps =
      if isDarwin
      then [
        boost
        boost.dev
        bzip2
        curl
        fmt
        icu
        jemalloc
        libevent
        lz4
        messagePack
        ncurses
        openpam
        openssl
        pcre2
        snappy
        xz
        zlib
        zstd
      ]
      else
        [
          boost
          bzip2
          curl
          fmt
          icu
          jemalloc
          libaio
          libevent
          liburing
          lz4
          messagePack
          ncurses
          numactl
          linux-pam
          openssl
          pcre2
          snappy
          systemd
          xz
          zlib
          zstd
        ]
        ++ [bash coreutils sed control];
    propagatedDeps = [];
    inherit expose configModule;

    phases = [
      {
        name = "unpack";
        script =
          if isDarwin
          then ''
            tar xf $src
            cd mariadb-${version}

            # MariaDB's generic hardening probe tests ELF-only -z flags with
            # CMake's cross static-library mode, which cannot reject linker
            # options. The AOS wrapper already injects the corresponding
            # Darwin hardening, so keep SECURITY_HARDENED enabled while
            # omitting only this inapplicable upstream ELF flag block.
            sed -i \
              's/IF(SECURITY_HARDENED AND /IF(SECURITY_HARDENED AND NOT APPLE AND /' \
              CMakeLists.txt

            # mysql.cc assumes every Apple SDK supplies the system libedit
            # compatibility header even after CMake selected MariaDB's bundled
            # readline implementation. The public source SDK intentionally has
            # no host-provided libedit; include the implementation selected by
            # MYSQL_CHECK_READLINE through MY_READLINE_INCLUDE_DIR instead.
            sed -i \
              '/#  include <editline\/readline.h>/a\#  include <history.h>' \
              client/mysql.cc
            sed -i \
              's|#  include <editline/readline.h>|#  include <readline.h>|' \
              client/mysql.cc
          ''
          else ''
            tar xf $src
            cd mariadb-${version}
          '';
      }
      {
        name = "configure";
        script =
          if isDarwin
          then ''
            mkdir build
            cd build
            cmake .. \
              $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX=$out \
              -DCMAKE_TRY_COMPILE_TARGET_TYPE=EXECUTABLE \
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
              -DWITH_LIBFMT=system \
              -DHAVE_SYSTEM_LIBFMT:BOOL=ON \
              -DLIBFMT_INCLUDE_DIR=${fmt}/include \
              -DLibfmt_core_h=${fmt}/include/fmt/core.h \
              -DGRN_WITH_LIBEVENT:STRING=${libevent} \
              -DGRN_WITH_MESSAGE_PACK:STRING=${messagePack} \
              -DCURSES_LIBRARY=${ncurses}/lib/libncursesw.dylib \
              -DCURSES_INCLUDE_PATH=${ncurses}/include \
              -DLZ4_LIBRARIES=${lz4}/lib/liblz4.dylib \
              -DLZ4_INCLUDE_DIRS=${lz4}/include \
              -DBZIP2_LIBRARIES=${bzip2}/lib/libbz2.dylib \
              -DBZIP2_INCLUDE_DIR=${bzip2}/include \
              -DSNAPPY_LIBRARIES=${snappy}/lib/libsnappy.dylib \
              -DSNAPPY_INCLUDE_DIRS=${snappy}/include \
              -DSnappy_LIBRARIES=${snappy}/lib/libsnappy.dylib \
              -DSnappy_INCLUDE_DIRS=${snappy}/include \
              -DZSTD_LIBRARIES=${zstd}/lib/libzstd.dylib \
              -DZSTD_INCLUDE_DIRS=${zstd}/include \
              -DWITH_JEMALLOC:STRING=yes \
              -DWITH_NUMA:BOOL=OFF \
              -DWITH_ROCKSDB_BZip2:STRING=ON \
              -DWITH_ROCKSDB_LZ4:STRING=ON \
              -DWITH_ROCKSDB_Snappy:STRING=ON \
              -DWITH_ROCKSDB_ZSTD:STRING=ON \
              -DWITH_SYSTEMD:STRING=no \
              -DWITH_UNIT_TESTS:BOOL=ON \
              -DPLUGIN_COLUMNSTORE:STRING=NO \
              -DAWS_SDK_EXTERNAL_PROJECT:BOOL=OFF \
              -DHAVE_ACCEPT4:INTERNAL=0 \
              -DHAVE_AUXV_GETAUXVAL:INTERNAL=0 \
              -DHAVE_BFILL:INTERNAL=0 \
              -DHAVE_GETPASSPHRASE:INTERNAL=0 \
              -DHAVE_MALLOC_USABLE_SIZE:INTERNAL=0 \
              -DHAVE_NETDB_H:INTERNAL=1 \
              -DHAVE_PAM_SYSLOG:INTERNAL=0 \
              -DHAVE_SCHED_GETCPU:INTERNAL=0 \
              -DHAVE_SIGWAITINFO:INTERNAL=0 \
              -DHAVE__STRTOUI64:INTERNAL=0 \
              -DBOOST_ROOT=${boost.dev} \
              -DIMPORT_EXECUTABLES=${nativeGenerators}/import_executables.cmake

            # Linux-only acceleration is replaced by the upstream Darwin
            # thread-pool and libc interfaces; all portable community plugins,
            # compression providers, PAM, TLS, and allocators remain enabled.
            for setting in \
              'BUILD_CONFIG:.*=mysql_release' \
              'FEATURE_SET:.*=community' \
              'WITH_SSL:.*=system' \
              'WITH_ZLIB:.*=system' \
              'WITH_ZSTD:.*=system' \
              'WITH_PCRE:.*=system' \
              'GRN_WITH_LIBEVENT:STRING=${libevent}' \
              'GRN_WITH_MESSAGE_PACK:STRING=${messagePack}' \
              'WITH_JEMALLOC:STRING=yes' \
              'WITH_NUMA:BOOL=OFF' \
              'WITH_ROCKSDB_BZip2:STRING=ON' \
              'WITH_ROCKSDB_LZ4:STRING=ON' \
              'WITH_ROCKSDB_Snappy:STRING=ON' \
              'WITH_ROCKSDB_ZSTD:STRING=ON' \
              'WITH_SYSTEMD:STRING=no' \
              'WITH_UNIT_TESTS:BOOL=ON' \
              'PLUGIN_COLUMNSTORE:STRING=NO' \
              'AWS_SDK_EXTERNAL_PROJECT:BOOL=OFF'; do
              grep "^$setting$" CMakeCache.txt
            done
            grep '^#define HAVE_SYSTEMD 1$' include/my_config.h && {
              echo "ERROR: MariaDB unexpectedly enabled systemd on Darwin" >&2
              exit 1
            }
            for unavailable in \
              HAVE_ACCEPT4 HAVE_AUXV_GETAUXVAL HAVE_BFILL \
              HAVE_GETPASSPHRASE HAVE_MALLOC_USABLE_SIZE HAVE_PAM_SYSLOG \
              HAVE_SCHED_GETCPU HAVE_SIGWAITINFO HAVE__STRTOUI64; do
              grep "^#define $unavailable 1$" include/my_config.h && {
                echo "ERROR: MariaDB detected unavailable Darwin libc API $unavailable" >&2
                exit 1
              }
            done
            grep '^PLUGIN_AUTH_PAM:BOOL=YES$' CMakeCache.txt
            cd ..
          ''
          else ''
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
              -DWITH_LIBFMT=system \
              -DHAVE_SYSTEM_LIBFMT:BOOL=ON \
              -DLIBFMT_INCLUDE_DIR=${fmt}/include \
              -DLibfmt_core_h=${fmt}/include/fmt/core.h \
              -DGRN_WITH_LIBEVENT:STRING=${libevent} \
              -DGRN_WITH_MESSAGE_PACK:STRING=${messagePack} \
              -DCURSES_LIBRARY=${ncurses}/lib/libncursesw.so \
              -DCURSES_INCLUDE_PATH=${ncurses}/include \
              -DLZ4_LIBRARIES=${lz4}/lib/liblz4.so \
              -DLZ4_INCLUDE_DIRS=${lz4}/include \
              -DBZIP2_LIBRARIES=${bzip2}/lib/libbz2.so \
              -DBZIP2_INCLUDE_DIR=${bzip2}/include \
              -DSNAPPY_LIBRARIES=${snappy}/lib/libsnappy.so \
              -DSNAPPY_INCLUDE_DIRS=${snappy}/include \
              -DSnappy_LIBRARIES=${snappy}/lib/libsnappy.so \
              -DSnappy_INCLUDE_DIRS=${snappy}/include \
              -DZSTD_LIBRARIES=${zstd}/lib/libzstd.so \
              -DZSTD_INCLUDE_DIRS=${zstd}/include \
              -DLIBAIO_LIBRARIES=${libaio}/lib/libaio.so \
              -DLIBAIO_INCLUDE_DIRS=${libaio}/include \
              -DURING_LIBRARIES=${liburing}/lib/liburing.so \
              -DURING_INCLUDE_DIRS=${liburing}/include \
              -DWITH_JEMALLOC:STRING=yes \
              -DWITH_NUMA:BOOL=ON \
              -DWITH_LIBURING:BOOL=ON \
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
              'GRN_WITH_MESSAGE_PACK:STRING=${messagePack}' \
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
            cd ..
          '';
      }
      {
        name = "build";
        script = ''
          (
            cd build
            make -j$NIX_BUILD_CORES
          )
        '';
      }
      {
        name = "install";
        script =
          (
            if isDarwin
            then ''
              cd build
              make install

              # These native test-suite helpers are installed below the usual
              # bin/sbin/libexec roots, so the generic fixup does not discover
              # them as executables. Strip their Mach-O symbols explicitly via
              # the Darwin wrapper to remove build-tree N_OSO string-table data.
              for helper in my_safe_process wsrep_check_version; do
                "$STRIP" --strip-unneeded \
                  "$out/mariadb-test/lib/My/SafeProcess/$helper"
              done

              test -f "$out/lib/plugin/ha_rocksdb.so"
              "$OBJDUMP" --macho --dylibs-used \
                "$out/lib/plugin/ha_rocksdb.so" > rocksdb-needed.txt
              for library in libbz2 liblz4 libsnappy libzstd; do
                grep "$library" rocksdb-needed.txt
              done

              test -f "$out/lib/plugin/ha_mroonga.so"
              # Groonga gates its libevent consumers on a combined suggestion
              # feature set. Darwin's linker dead-strips libevent from targets
              # which do not call it, so prove provider detection in the cache
              # instead of requiring every Mroonga module to retain the dylib.
              grep '^HAVE_LIBEVENT:INTERNAL=1$' CMakeCache.txt
              grep '^#define GRN_WITH_MESSAGE_PACK$' \
                storage/mroonga/vendor/groonga/config.h
              grep '^MESSAGE_PACK_FOUND:INTERNAL=1$' CMakeCache.txt
              grep '^MESSAGE_PACK_LIBRARIES:INTERNAL=msgpackc$' CMakeCache.txt
              test -f "$out/lib/plugin/auth_pam.so"
              "$OBJDUMP" --macho --dylibs-used \
                "$out/lib/plugin/auth_pam.so" | grep libpam

              mkdir -p "$out/share/aos-build-features"
              grep -E \
                '^(BUILD_CONFIG|FEATURE_SET|WITH_SSL|WITH_ZLIB|WITH_ZSTD|WITH_PCRE|GRN_WITH_LIBEVENT|GRN_WITH_MESSAGE_PACK|WITH_JEMALLOC|WITH_NUMA|WITH_ROCKSDB_BZip2|WITH_ROCKSDB_LZ4|WITH_ROCKSDB_Snappy|WITH_ROCKSDB_ZSTD|WITH_SYSTEMD|WITH_UNIT_TESTS|PLUGIN_COLUMNSTORE|AWS_SDK_EXTERNAL_PROJECT|PLUGIN_AUTH_PAM):' \
                CMakeCache.txt > "$out/share/aos-build-features/mariadb-cmake-cache.txt"
            ''
            else ''
              cd build
              make install

              # Prove the requested features reached built artifacts, not merely
              # the CMake cache. MariaRocks vendors its matched RocksDB source but
              # must link every distributable compression and I/O provider from
              # AOS packages; Mroonga is the sole libevent consumer.
              test -f "$out/lib/plugin/ha_rocksdb.so"
              readelf -d "$out/lib/plugin/ha_rocksdb.so" > rocksdb-needed.txt
              for library in libbz2 liblz4 libsnappy liburing libzstd; do
                grep "$library" rocksdb-needed.txt
              done
              test -f "$out/lib/plugin/ha_mroonga.so"
              readelf -d "$out/lib/plugin/ha_mroonga.so" | grep libevent
              grep '^#define GRN_WITH_MESSAGE_PACK$' \
                storage/mroonga/vendor/groonga/config.h
              grep '^MESSAGE_PACK_FOUND:INTERNAL=1$' CMakeCache.txt
              grep '^MESSAGE_PACK_LIBRARIES:INTERNAL=msgpackc$' CMakeCache.txt

              mkdir -p "$out/share/aos-build-features"
              grep -E \
                '^(BUILD_CONFIG|FEATURE_SET|WITH_SSL|WITH_ZLIB|WITH_ZSTD|WITH_PCRE|GRN_WITH_LIBEVENT|GRN_WITH_MESSAGE_PACK|WITH_JEMALLOC|WITH_NUMA|WITH_LIBURING|WITH_ROCKSDB_BZip2|WITH_ROCKSDB_LZ4|WITH_ROCKSDB_Snappy|WITH_ROCKSDB_ZSTD|WITH_SYSTEMD|WITH_UNIT_TESTS|PLUGIN_COLUMNSTORE|AWS_SDK_EXTERNAL_PROJECT):' \
                CMakeCache.txt > "$out/share/aos-build-features/mariadb-cmake-cache.txt"
            ''
          )
          + ''
            install -m 0755 "$out/scripts/mariadb-install-db" "$out/bin/mariadb-install-db"
            sed -i '1c#!${bash}/bin/bash' "$out/bin/mariadb-install-db"
            ln -s ${control}/bin/mariadb-control "$out/bin/mariadb-control"
            test -x "$out/bin/mariadb-install-db"
            test -x "$out/bin/mariadb-control"
          '';
      }
    ];

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
        # Do not consult the host's /etc/my.cnf.d while checking the packaged
        # server binary.
        command = "mariadbd --no-defaults --version";
      };

      features = testing.mkVMTest {
        name = "storage-mariadb-features";
        rootfsDeps = [self];
        testScript = ''
          features=${self}/share/aos-build-features/mariadb-cmake-cache.txt
          grep '^BUILD_CONFIG:.*=mysql_release$' "$features"
          grep '^FEATURE_SET:.*=community$' "$features"
          grep '^WITH_SSL:.*=system$' "$features"
          grep '^WITH_ZLIB:.*=system$' "$features"
          grep '^WITH_ZSTD:.*=system$' "$features"
          grep '^WITH_PCRE:.*=system$' "$features"
          grep '^GRN_WITH_LIBEVENT:STRING=${libevent}$' "$features"
          grep '^GRN_WITH_MESSAGE_PACK:STRING=${messagePack}$' "$features"
          grep '^WITH_JEMALLOC:STRING=yes$' "$features"
          grep '^WITH_NUMA:BOOL=ON$' "$features"
          grep '^WITH_LIBURING:BOOL=ON$' "$features"
          grep '^WITH_ROCKSDB_BZip2:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_LZ4:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_Snappy:STRING=ON$' "$features"
          grep '^WITH_ROCKSDB_ZSTD:STRING=ON$' "$features"
          grep '^WITH_SYSTEMD:STRING=yes$' "$features"
          grep '^WITH_UNIT_TESTS:BOOL=ON$' "$features"
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
