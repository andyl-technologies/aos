##! bind — Authoritative DNS server, recursive resolver, and DNS utilities
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  pkg-config,
  cmocka,
  libcap,
  libidn2,
  libmaxminddb,
  libtool,
  libxml2,
  openssl,
  liburcu,
  libuv,
  nghttp2,
  jemalloc,
  krb5,
  fstrm,
  protobuf-c,
  lmdb,
  json-c,
  zlib,
  readline,
}: let
  version = "9.20.26";
in
  mkDerivation {
    pname = "bind";
    inherit version;
    outputs = ["out" "dnsutils"];

    src = fetchurl {
      urls = [
        "https://downloads.isc.org/isc/bind9/${version}/bind-${version}.tar.xz"
      ];
      hash = "sha256-VSSN7w+HDExGs95yl46pcmFRMVFmYxiKRWTcodIL81A=";
    };

    buildDeps = [gnumake perl pkg-config cmocka];
    runtimeDeps = [
      libcap
      libidn2
      libmaxminddb
      libtool
      libxml2
      openssl
      liburcu
      libuv
      nghttp2
      jemalloc
      krb5
      fstrm
      protobuf-c
      lmdb
      json-c
      zlib
      readline
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd bind-${version}

          # This timezone-formatting case relies on host timezone data and is
          # not deterministic in a hermetic build sandbox.
          sed -i '/^ISC_TEST_ENTRY(isc_time_formatISO8601L/d' tests/isc/time_test.c

          # These are scheduler-sensitive performance benchmarks with a fixed
          # watchdog, rather than rwlock/mutex correctness tests. Concurrent
          # hermetic builds can exhaust the watchdog on otherwise healthy hosts.
          sed -i '/^ISC_TEST_ENTRY(isc_mutex_benchmark/d' tests/isc/mutex_test.c
          sed -i '/^ISC_TEST_ENTRY_CUSTOM(isc_rwlock_benchmark/d' tests/isc/rwlock_test.c
          sed -i '/^ISC_TEST_ENTRY(isc_spinlock_benchmark/d' tests/isc/spinlock_test.c
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir="$out/etc" \
            --localstatedir=/var \
            --enable-dnstap \
            --enable-doh \
            --enable-geoip \
            --enable-year2038 \
            --enable-full-report \
            --with-liburcu=membarrier \
            --with-maxminddb=${libmaxminddb} \
            --with-libnghttp2=yes \
            --with-openssl=${openssl} \
            --with-gssapi=${krb5}/bin/krb5-config \
            --with-lmdb=${lmdb} \
            --with-libxml2=yes \
            --with-json-c=yes \
            --with-zlib=yes \
            --with-readline=readline \
            --with-libidn2=${libidn2} \
            --with-cmocka=detect \
            --with-jemalloc=detect
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          # BIND defaults each test binary to one loop worker per detected CPU.
          # Large builders can then expose an upstream netmgr teardown race in
          # qpdb_test, while two workers still exercise its concurrent paths.
          ISC_TASK_WORKERS=2 make -j"$NIX_BUILD_CORES" unit
        '';
      }
      {
        name = "install";
        script = ''
          make install

          mkdir -p "$dnsutils/bin" "$dnsutils/share/man/man1"
          for tool in delv dig host mdig nslookup nsupdate; do
            if [ -x "$out/bin/$tool" ]; then
              mv "$out/bin/$tool" "$dnsutils/bin/"
            fi
            if [ -f "$out/share/man/man1/$tool.1" ]; then
              mv "$out/share/man/man1/$tool.1" "$dnsutils/share/man/man1/"
            fi
          done

          mkdir -p "$out/etc"
          cat > "$out/etc/rndc.conf" << EOF
          include "/etc/bind/rndc.key";
          options {
              default-key "rndc-key";
              default-server 127.0.0.1;
              default-port 953;
          };
          EOF
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-bind-dns";
        library = self;
        libs = ["-ldns" "-lisc"];
        testSource = ''
          #include <dns/version.h>
          #include <isc/version.h>

          int main(void) {
              return dns_version == NULL || isc_version == NULL;
          }
        '';
      };
      server = testing.mkToolCheck {
        pname = "tool-bind";
        tool = self;
        command = "named -V";
      };
      dnsutils = testing.mkToolCheck {
        pname = "tool-dnsutils";
        tool = self.dnsutils;
        command = "dig -v && nslookup -version";
      };
    };

    meta = {
      description = "Authoritative DNS server and recursive resolver";
      homepage = "https://www.isc.org/bind/";
      license = "MPL-2.0";
      mainProgram = "named";
    };
  }
