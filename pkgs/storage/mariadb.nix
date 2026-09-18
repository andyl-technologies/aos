##! MariaDB — Community relational database server
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  bison,
  git,
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
  libxcrypt,
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
  version = "12.3.3";
  isDarwin = stdenv.hostPlatform.isDarwin;
  # MariaDB's CPU-specific sources recognize aarch64 rather than arm64.
  # Keep the cross toolchain and execution wrapper while using that spelling.
  linuxCrossCmakeFlags = lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) " $cmakeFlags -DCMAKE_SYSTEM_PROCESSOR=${stdenv.hostPlatform.parsed.cpu.name}";
  source = fetchurl {
    urls = [
      "https://archive.mariadb.org/mariadb-${version}/source/mariadb-${version}.tar.gz"
    ];
    hash = "sha256-6Z1zn9SlX5oR3qe9IoeiYmc+KHVQrzBxyEad0r7AwWM=";
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
            -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
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
          buildPackages.git
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

    program_dir="''${0%/*}"
    case "''${1:-}" in
      init)
        config=$2
        state=$3
        if [[ ! -d "$state/mysql" ]]; then
          exec "$program_dir/mariadb-install-db" \
            --defaults-file="$config" \
            --auth-root-authentication-method=socket \
            --force \
            --skip-test-db
        fi
        ;;
      run)
        config=$2
        exec "$program_dir/mariadbd" --defaults-file="$config"
        ;;
      *) echo "usage: mariadb-control init CONFIG STATE | mariadb-control run CONFIG" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "mariadb";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "MariaDB prints the two normalized command-line options in declaration order.";
        "files" = {
          "my.cnf" = "[client]\nuser=qualification\nport=4242\n";
        };
        "input" = "A client option group declaring a user and TCP port.";
        "operation" = "Read the group through my_print_defaults.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/my_print_defaults"
              "--defaults-file=@work@/primary/my.cnf"
              "client"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "--user=qualification\n--port=4242\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "MariaDB rejects the group syntax with status 2.";
        "files" = {
          "my.cnf" = "[client\nuser=qualification\n";
        };
        "input" = "An option file with an unterminated client group header.";
        "operation" = "Read the malformed option file through my_print_defaults.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/my_print_defaults"
              "--defaults-file=@work@/bad-input/my.cnf"
              "client"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = source;

    buildDeps =
      if isDarwin
      then [
        buildPackages.gnumake
        buildPackages.cmake
        buildPackages.bison
        buildPackages.git
        buildPackages.pkg-config
        buildPackages.perl
        buildPackages.python3
        buildPackages.rpcsvc-proto
      ]
      else [
        gnumake
        cmake
        bison
        git
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
          # The server and backup tool link crypt directly on Linux.
          libxcrypt
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
    abilities = ./_mariadb;

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
            cmake ..${linuxCrossCmakeFlags} \
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
          ''
          + lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # These installed test helpers sit outside the usual binary
            # directories. Drop compiler paths retained in their DWARF data.
            for helper in my_safe_process wsrep_check_version; do
              "${stdenv.cc}/bin/strip" --strip-debug "$out/mariadb-test/lib/My/SafeProcess/$helper"
            done
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
      mkSystem,
    }: let
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "system-image";
        key = "mariadb-package-check";
        stage = "host";
      };
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      secret = name:
        lib.abilities.resourceReference {
          interface = serviceManagement.interfaces.credentialDelivery.identity;
          resource = {
            provider = credentialProvider;
            key = name;
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
      evaluate = mariadbConfig:
        mkSystem {
          systemName = "mariadb-package-check";
          modules = [
            {
              environment.systemPackages = [self];
              mariadb = mariadbConfig;
            }
          ];
        };
      variants = [
        {
          tls = false;
          ca = false;
          admin = false;
          replication = false;
        }
        {
          tls = false;
          ca = false;
          admin = false;
          replication = true;
        }
        {
          tls = false;
          ca = false;
          admin = true;
          replication = false;
        }
        {
          tls = false;
          ca = false;
          admin = true;
          replication = true;
        }
        {
          tls = true;
          ca = false;
          admin = false;
          replication = false;
        }
        {
          tls = true;
          ca = false;
          admin = false;
          replication = true;
        }
        {
          tls = true;
          ca = false;
          admin = true;
          replication = false;
        }
        {
          tls = true;
          ca = false;
          admin = true;
          replication = true;
        }
        {
          tls = true;
          ca = true;
          admin = false;
          replication = false;
        }
        {
          tls = true;
          ca = true;
          admin = false;
          replication = true;
        }
        {
          tls = true;
          ca = true;
          admin = true;
          replication = false;
        }
        {
          tls = true;
          ca = true;
          admin = true;
          replication = true;
        }
      ];
      configFor = variant: {
        enable = true;
        bindAddress = "127.0.0.1";
        maxConnections = 200;
        tls =
          {enable = variant.tls;}
          // lib.optionalAttrs variant.tls {
            certificate.resource = secret "tls-certificate";
            privateKey.resource = secret "tls-private-key";
          }
          // lib.optionalAttrs variant.ca {
            ca.resource = secret "tls-ca";
          };
        bootstrap =
          lib.optionalAttrs variant.admin {
            adminSql.resource = secret "admin-bootstrap-sql";
          }
          // lib.optionalAttrs variant.replication {
            replicationSql.resource = secret "replication-bootstrap-sql";
          };
      };
      evaluations = builtins.map (variant: evaluate (configFor variant)) variants;
      evaluated = builtins.elemAt evaluations ((builtins.length evaluations) - 1);
      plainEvaluated = builtins.head evaluations;
      disabled = evaluate {};
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      ownedValues = lib.filterAttrs (_: value: value.package == self.pname);
      invalidTls = evaluate {
        enable = true;
        tls = {
          enable = true;
          certificate.resource = secret "tls-certificate";
        };
      };
      disabledTlsCredentials = evaluate {
        tls.certificate.resource = secret "tls-certificate";
      };
      disabledIncompleteTls = evaluate {
        tls.enable = true;
      };
      enabledAbilityConfig = evaluated.config.aos.abilities;
      plainAbilityConfig = plainEvaluated.config.aos.abilities;
      disabledAbilityConfig = disabled.config.aos.abilities;
      requests = builtins.attrNames enabledAbilityConfig.requests;
      plainRequests = builtins.attrNames plainAbilityConfig.requests;
      disabledRequirements = builtins.attrNames disabledAbilityConfig.requirementTemplates;
      serverSource = enabledAbilityConfig.requests."mariadb:server-configuration".parameters.source;
      bootstrapSource = enabledAbilityConfig.requests."mariadb:bootstrap-configuration".parameters.source;
      serverLiteralText = lib.concatStringsSep "" (builtins.map
        (fragment:
          if fragment.kind == "literal"
          then fragment.text
          else "")
        serverSource.fragments);
      mainLifecycle = enabledAbilityConfig.requests."mariadb:main-lifecycle".parameters;
      mainDependencies = enabledAbilityConfig.requests."mariadb:main-dependencies".parameters;
      mainStorage = enabledAbilityConfig.requests."mariadb:main-storage".parameters;
      servicePrincipal = enabledAbilityConfig.requests."mariadb:service-principal".parameters;
      expectedRequestOutput = localKey: output: {
        package = self.pname;
        inherit localKey output;
      };
      configurationPathIdentity = localKey: let
        expectedIdentity = expectedRequestOutput localKey "planned-path";
        executionPathIdentities =
          builtins.map
          (fragment:
            lib.abilities.requestOutputIdentity {
              requests = enabledAbilityConfig.requests;
              reference = fragment.value;
            })
          (builtins.filter
            (fragment: fragment.kind == "execution-path")
            serverSource.fragments);
        matches =
          builtins.filter
          (identity: identity == expectedIdentity)
          executionPathIdentities;
        matchCount = builtins.length matches;
      in
        if matchCount == 1
        then builtins.head matches
        else
          throw
          "MariaDB ability contract fixture expected exactly one '${localKey}' planned execution path, found ${builtins.toString matchCount}.";
      lifecycleConfig = pkgs.writeTextFile {
        name = "mariadb-lifecycle-config";
        destination = "/my.cnf";
        # This fixture exercises the packaged binary. Production paths come
        # only from typed provider outputs in the ability module above.
        text = ''
          [client]
          socket=/run/mariadb/mariadb.sock
          port=3306

          [mariadbd]
          bind-address=127.0.0.1
          port=3306
          socket=/run/mariadb/mariadb.sock
          pid-file=/run/mariadb/mariadb.pid
          datadir=/var/lib/aos-pkg-mariadb
          log-error=/var/log/mariadb/error.log
          character-set-server=utf8mb4
          collation-server=utf8mb4_uca1400_ai_ci
          max-connections=200
          skip-name-resolve=ON
          sql-mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
          skip-ssl
        '';
      };
      allVariantsEvaluate = builtins.all assertionsHold evaluations;
      contractHolds =
        allVariantsEvaluate
        && lib.abilities.types.isPortableOptionTree evaluated.options.mariadb
        && assertionsHold disabledTlsCredentials
        && assertionsHold disabledIncompleteTls
        && !assertionsHold invalidTls
        && ownedValues disabledAbilityConfig.instances == {}
        && ownedValues disabledAbilityConfig.requests == {}
        && builtins.elem "mariadb:credential-delivery" disabledRequirements
        && builtins.elem "mariadb:service-credentials" disabledRequirements
        && builtins.elem "mariadb:service-lifecycle" disabledRequirements
        && builtins.elem "mariadb:initialize-lifecycle" requests
        && builtins.elem "mariadb:main-lifecycle" requests
        && builtins.elem "mariadb:credential-tls-certificate" requests
        && builtins.elem "mariadb:credential-tls-private-key" requests
        && builtins.elem "mariadb:credential-tls-ca" requests
        && builtins.elem "mariadb:credential-admin-bootstrap-sql" requests
        && builtins.elem "mariadb:credential-replication-bootstrap-sql" requests
        && !(builtins.elem "mariadb:credential-tls-certificate" plainRequests)
        && !(builtins.elem "mariadb:bootstrap-configuration" plainRequests)
        && !(builtins.elem "mariadb:main-credentials" plainRequests)
        && serverSource.kind == "interpolated-text"
        && bootstrapSource.kind == "interpolated-text"
        && bootstrapSource.maximum_size_bytes == lib.abilities.types.limits.maxDocumentBytes
        && lib.hasInfix "bind-address=127.0.0.1" serverLiteralText
        && lib.hasInfix "max-connections=200" serverLiteralText
        && lib.hasInfix "ssl-cert=" serverLiteralText
        && lib.hasInfix "ssl-key=" serverLiteralText
        && lib.hasInfix "ssl-ca=" serverLiteralText
        && !(lib.hasInfix "/etc/" (builtins.toJSON serverSource))
        && !(lib.hasInfix "/var/lib/" (builtins.toJSON serverSource))
        && !(lib.hasInfix "MARIADB_CONFIG_GENERATION" (builtins.toJSON enabledAbilityConfig.requests))
        && mainLifecycle.restart == "on-failure"
        && mainLifecycle.configuration_change_action == "restart"
        && lib.abilities.requestOutputIdentity {
          requests = enabledAbilityConfig.requests;
          reference = servicePrincipal.home_directory;
        }
        == expectedRequestOutput "state-storage" "planned-path"
        && builtins.map
        (mount:
          lib.abilities.requestOutputIdentity {
            requests = enabledAbilityConfig.requests;
            reference = mount.source;
          })
        mainStorage.mounts
        == [
          (expectedRequestOutput "state-storage" "planned-path")
          (expectedRequestOutput "runtime-storage" "planned-path")
          (expectedRequestOutput "log-storage" "planned-path")
        ]
        && configurationPathIdentity "state-storage"
        == expectedRequestOutput "state-storage" "planned-path"
        && configurationPathIdentity "runtime-storage"
        == expectedRequestOutput "runtime-storage" "planned-path"
        && configurationPathIdentity "log-storage"
        == expectedRequestOutput "log-storage" "planned-path"
        && (builtins.elemAt mainLifecycle.start 0).executable.entry_point == "bin/mariadb-control"
        && lib.abilities.requestOutputIdentity {
          requests = enabledAbilityConfig.requests;
          reference = builtins.elemAt mainDependencies.after 0;
        }
        == expectedRequestOutput "initialize-lifecycle" "resource"
        && !(enabledAbilityConfig.requests."mariadb:service-group".parameters ? requested_id)
        && !(enabledAbilityConfig.requests."mariadb:service-principal".parameters ? requested_id);
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

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "storage-mariadb-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the MariaDB ability module contract checks failed";

      lifecycle = import ./_mariadb-tests/lifecycle.nix {
        inherit testing self;
        renderedFile = lifecycleConfig;
        coreutils = pkgs.coreutils;
        grep = pkgs.grep;
        iproute2 = pkgs.iproute2;
        sed = pkgs.sed;
      };
    };
  }
