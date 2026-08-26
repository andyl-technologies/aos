##! curl — Command-line URL transfer tool
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  perl,
  openssl,
  zlib,
  nghttp2,
  ca-certificates,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "8.12.1";
in
  mkDerivation {
    pname = "curl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://curl.se/download/curl-${version}.tar.xz"
      ];
      hash = "sha256-A0Hx7ZeibIEauuvTfWK4M5VnkrdgfqPxXQAWE8dt4gI=";
    };

    buildDeps = [
      gnumake
      pkg-config
      perl
    ];
    runtimeDeps =
      [
        openssl
        zlib
        nghttp2
        ca-certificates
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [
      openssl
      zlib
      nghttp2
    ];

    # Guard: keep the autotools build toolchain out of curl's
    # `--version`-baked CC/PKG_CONFIG_PATH strings.
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd curl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-openssl=${openssl} \
            --with-zlib=${zlib} \
            --with-nghttp2=${nghttp2} \
            --with-ca-bundle=${ca-certificates}/etc/ssl/certs/ca-certificates.crt \
            --enable-shared \
            --disable-static \
            --disable-ldap \
            --disable-ldaps \
            --without-librtmp \
            --without-libpsl \
            --without-libidn2 \
            --enable-threaded-resolver \
            --enable-ipv6 \
            --disable-docs \
            --disable-manual
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/curl-config"
            # Create curl.pc symlink (some consumers look for "curl" not "libcurl")
            ln -sf libcurl.pc $out/lib/pkgconfig/curl.pc
          ''
          else ''
            make install
            # Create curl.pc symlink (some consumers look for "curl" not "libcurl")
            ln -sf libcurl.pc $out/lib/pkgconfig/curl.pc
          '';
      }
    ];

    meta = {
      description = "curl — command-line tool for transferring data via URLs";
      homepage = "https://curl.se";
      license = "curl";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-curl";
        tool = self;
        command = "curl --version";
        extraDeps = [
          pkgs.openssl
          pkgs.zlib
        ];
      };

      link = testing.mkLinkCheck {
        pname = "lib-curl";
        library = self;
        libs = ["-lcurl"];
        extraDeps = [
          pkgs.openssl
          pkgs.zlib
        ];
        testSource = ''
          #include <curl/curl.h>
          #include <stdio.h>
          int main() {
            printf("curl version: %s\n", curl_version());
            return 0;
          }
        '';
      };

      easy = testing.mkLinkCheck {
        pname = "lib-curl-easy";
        library = self;
        libs = ["-lcurl"];
        extraDeps = [
          pkgs.openssl
          pkgs.zlib
        ];
        testSource = ''
          #include <curl/curl.h>
          #include <stdio.h>
          int main() {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            CURL *c = curl_easy_init();
            if (!c) return 1;
            curl_easy_cleanup(c);
            curl_global_cleanup();
            printf("curl easy init/cleanup: PASS\n");
            return 0;
          }
        '';
      };

      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["curl"];
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libcurl.so"];
      };

      tls-stack = testing.mkVMTest {
        name = "cross-cutting-tls-stack";
        rootfsDeps = [
          pkgs.openssl
          self
        ];
        testScript = ''
          export C_INCLUDE_PATH="${pkgs.openssl}/include:${self}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.openssl}/lib:${self}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${self}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/tls_test.c << 'EOF'
          #include <curl/curl.h>
          #include <openssl/opensslv.h>
          #include <openssl/crypto.h>
          #include <stdio.h>

          int main(void) {
              curl_global_init(CURL_GLOBAL_DEFAULT);
              CURL *handle = curl_easy_init();
              if (!handle) {
                  fprintf(stderr, "curl_easy_init failed\n");
                  return 1;
              }

              /* curl is built with a compiled-in default CA bundle; confirm it
                 resolves to a readable file without any caller-supplied
                 override. */
              char *cainfo = NULL;
              curl_easy_getinfo(handle, CURLINFO_CAINFO, &cainfo);
              if (!cainfo) {
                  fprintf(stderr, "curl has no default CA bundle\n");
                  return 1;
              }
              FILE *ca = fopen(cainfo, "r");
              if (!ca) {
                  fprintf(stderr, "default CA bundle is not readable: %s\n", cainfo);
                  return 1;
              }
              fclose(ca);

              printf("curl version: %s\n", curl_version());
              printf("openssl header: %s\n", OPENSSL_VERSION_TEXT);
              printf("openssl runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
              printf("CA bundle: %s\n", cainfo);

              curl_easy_cleanup(handle);
              curl_global_cleanup();
              printf("TLS stack integration: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling TLS stack test"
          gcc -o /tmp/tls_test /tmp/tls_test.c -lcurl -lssl -lcrypto
          echo "==> Running TLS stack test"
          /tmp/tls_test
        '';
      };

      tls-full-chain = testing.mkVMTest {
        name = "cross-cutting-tls-full-chain";
        rootfsDeps = [
          pkgs.openssl
          pkgs.libssh2
          self
          pkgs.nghttp2
        ];
        testScript = ''
          export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.libssh2}/include:${self}/include:${pkgs.nghttp2}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.libssh2}/lib:${self}/lib:${pkgs.nghttp2}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.libssh2}/lib:${self}/lib:${pkgs.nghttp2}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/tls_full.c << 'EOF'
          #include <openssl/crypto.h>
          #include <openssl/ssl.h>
          #include <libssh2.h>
          #include <curl/curl.h>
          #include <nghttp2/nghttp2.h>
          #include <stdio.h>

          int main(void) {
              printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));

              int rc = libssh2_init(0);
              if (rc != 0) {
                  fprintf(stderr, "libssh2_init failed: %d\n", rc);
                  return 1;
              }
              printf("libssh2: initialized OK\n");
              libssh2_exit();
              printf("libssh2: cleaned up OK\n");

              curl_global_init(CURL_GLOBAL_DEFAULT);
              CURL *handle = curl_easy_init();
              if (!handle) {
                  fprintf(stderr, "curl_easy_init failed\n");
                  return 1;
              }
              printf("curl: %s\n", curl_version());
              curl_easy_cleanup(handle);
              curl_global_cleanup();

              nghttp2_info *info = nghttp2_version(0);
              printf("nghttp2: %s\n", info->version_str);

              printf("TLS full chain: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling TLS full chain test"
          gcc -o /tmp/tls_full /tmp/tls_full.c -lcurl -lssh2 -lssl -lcrypto -lnghttp2
          echo "==> Running TLS full chain test"
          /tmp/tls_full
        '';
      };

      multi-lib-link = testing.mkVMTest {
        name = "cross-cutting-multi-lib-link";
        rootfsDeps = [
          pkgs.openssl
          pkgs.zlib
          self
          pkgs.pcre2
        ];
        testScript = ''
          export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.zlib}/include:${self}/include:${pkgs.pcre2}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${self}/lib:${pkgs.pcre2}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${self}/lib:${pkgs.pcre2}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/multilib.c << 'EOF'
          #include <openssl/crypto.h>
          #include <zlib.h>
          #include <curl/curl.h>
          #define PCRE2_CODE_UNIT_WIDTH 8
          #include <pcre2.h>
          #include <stdio.h>

          int main(void) {
              printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));
              printf("zlib: %s\n", zlibVersion());
              printf("curl: %s\n", curl_version());
              printf("pcre2: %d.%d\n", PCRE2_MAJOR, PCRE2_MINOR);

              curl_global_init(CURL_GLOBAL_DEFAULT);
              CURL *c = curl_easy_init();
              if (!c) { fprintf(stderr, "curl_easy_init failed\n"); return 1; }
              curl_easy_cleanup(c);
              curl_global_cleanup();

              Bytef dst[256];
              uLong dLen = sizeof(dst);
              const char *src = "test";
              if (compress(dst, &dLen, (const Bytef *)src, 4) != Z_OK) {
                  fprintf(stderr, "zlib compress failed\n"); return 1;
              }

              printf("Multi-lib link: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling multi-library binary"
          gcc -o /tmp/multilib /tmp/multilib.c -lcurl -lssl -lcrypto -lz -lpcre2-8
          echo "==> Running multi-library binary"
          /tmp/multilib
        '';
      };
    };
  }
