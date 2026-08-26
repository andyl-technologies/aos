##! MariaDB — Community relational database server
{
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
}: let
  version = "11.4.12";
  isDarwin = stdenv.hostPlatform.isDarwin;
  source = fetchurl {
    urls = [
      "https://archive.mariadb.org/mariadb-${version}/source/mariadb-${version}.tar.gz"
    ];
    hash = "sha256-WreIPbUZv86/3SqsCbxVRKEs4yjznt1G0L8BaQYV72w=";
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
        runtimeDeps = [];
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
in
  mkDerivation {
    pname = "mariadb";
    inherit version;

    src = source;

    buildDeps = [
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
        bzip2
        curl
        icu
        jemalloc
        libevent
        lz4
        ncurses
        openpam
        openssl
        pcre2
        snappy
        xz
        zlib
        zstd
      ]
      else [
        boost
        bzip2
        curl
        icu
        jemalloc
        libaio
        libevent
        liburing
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
        script =
          if isDarwin
          then ''
            mkdir build
            cd build
            cmake .. \
              $cmakeFlags \
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
              -DWITH_NUMA:BOOL=OFF \
              -DWITH_ROCKSDB_BZip2:STRING=ON \
              -DWITH_ROCKSDB_LZ4:STRING=ON \
              -DWITH_ROCKSDB_Snappy:STRING=ON \
              -DWITH_ROCKSDB_ZSTD:STRING=ON \
              -DWITH_SYSTEMD:STRING=no \
              -DWITH_UNIT_TESTS:BOOL=ON \
              -DAWS_SDK_EXTERNAL_PROJECT:BOOL=OFF \
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
              'WITH_JEMALLOC:STRING=yes' \
              'WITH_NUMA:BOOL=OFF' \
              'WITH_ROCKSDB_BZip2:STRING=ON' \
              'WITH_ROCKSDB_LZ4:STRING=ON' \
              'WITH_ROCKSDB_Snappy:STRING=ON' \
              'WITH_ROCKSDB_ZSTD:STRING=ON' \
              'WITH_SYSTEMD:STRING=no' \
              'WITH_UNIT_TESTS:BOOL=ON' \
              'AWS_SDK_EXTERNAL_PROJECT:BOOL=OFF'; do
              grep "^$setting$" CMakeCache.txt
            done
            grep '^#define HAVE_SYSTEMD 1$' include/my_config.h && {
              echo "ERROR: MariaDB unexpectedly enabled systemd on Darwin" >&2
              exit 1
            }
            grep '^PLUGIN_AUTH_PAM:BOOL=YES$' CMakeCache.txt
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
              -DGRN_WITH_LIBEVENT:STRING=${libevent} \
              -DWITH_JEMALLOC:STRING=yes \
              -DWITH_NUMA:BOOL=ON \
              -DWITH_LIBURING:BOOL=ON \
              -DWITH_ROCKSDB_BZip2:STRING=ON \
              -DWITH_ROCKSDB_LZ4:STRING=ON \
              -DWITH_ROCKSDB_Snappy:STRING=ON \
              -DWITH_ROCKSDB_ZSTD:STRING=ON \
              -DWITH_SYSTEMD:STRING=yes \
              -DWITH_UNIT_TESTS:BOOL=ON \
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
              'AWS_SDK_EXTERNAL_PROJECT:BOOL=OFF'; do
              grep "^$setting$" CMakeCache.txt
            done
            grep '^#define HAVE_SYSTEMD 1$' include/my_config.h
          '';
      }
      {
        name = "build";
        script = ''
          cd build
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if isDarwin
          then ''
            cd build
            make install

            test -f "$out/lib/plugin/ha_rocksdb.so"
            "$OBJDUMP" --macho --dylibs-used \
              "$out/lib/plugin/ha_rocksdb.so" > rocksdb-needed.txt
            for library in libbz2 liblz4 libsnappy libzstd; do
              grep "$library" rocksdb-needed.txt
            done

            test -f "$out/lib/plugin/ha_mroonga.so"
            "$OBJDUMP" --macho --dylibs-used \
              "$out/lib/plugin/ha_mroonga.so" | grep libevent
            "$OBJDUMP" --macho --dylibs-used \
              "$out/bin/mariadbd" | grep libjemalloc
            test -f "$out/lib/plugin/auth_pam.so"
            "$OBJDUMP" --macho --dylibs-used \
              "$out/lib/plugin/auth_pam.so" | grep libpam

            mkdir -p "$out/share/aos-build-features"
            grep -E \
              '^(BUILD_CONFIG|FEATURE_SET|WITH_SSL|WITH_ZLIB|WITH_ZSTD|WITH_PCRE|GRN_WITH_LIBEVENT|WITH_JEMALLOC|WITH_NUMA|WITH_ROCKSDB_BZip2|WITH_ROCKSDB_LZ4|WITH_ROCKSDB_Snappy|WITH_ROCKSDB_ZSTD|WITH_SYSTEMD|WITH_UNIT_TESTS|AWS_SDK_EXTERNAL_PROJECT|PLUGIN_AUTH_PAM):' \
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
            readelf -d "$out/bin/mariadbd" | grep libjemalloc

            mkdir -p "$out/share/aos-build-features"
            grep -E \
              '^(BUILD_CONFIG|FEATURE_SET|WITH_SSL|WITH_ZLIB|WITH_ZSTD|WITH_PCRE|GRN_WITH_LIBEVENT|WITH_JEMALLOC|WITH_NUMA|WITH_LIBURING|WITH_ROCKSDB_BZip2|WITH_ROCKSDB_LZ4|WITH_ROCKSDB_Snappy|WITH_ROCKSDB_ZSTD|WITH_SYSTEMD|WITH_UNIT_TESTS|AWS_SDK_EXTERNAL_PROJECT):' \
              CMakeCache.txt > "$out/share/aos-build-features/mariadb-cmake-cache.txt"
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
      ...
    }: {
      version = testing.mkToolCheck {
        pname = "storage-mariadb";
        tool = self;
        command = "mariadbd --version";
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
    };
  }
