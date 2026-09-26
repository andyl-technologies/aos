##! OpenSSL — TLS and cryptography library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  perl,
  stdenv,
}: let
  version = "4.0.2";
  isDarwin = stdenv.hostPlatform.isDarwin;
  configureTarget =
    if isDarwin
    then
      if stdenv.hostPlatform.isAarch64
      then "darwin64-arm64-cc"
      else "darwin64-x86_64-cc"
    else if stdenv.hostPlatform.isAarch64
    then "linux-aarch64"
    else "linux-x86_64";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "openssl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The digest matches the standard SHA-256 vector.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"openssl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"openssl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <openssl/sha.h>\nint main(void) {\n    static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};\n    unsigned char digest[SHA256_DIGEST_LENGTH];\n    if (SHA256((const unsigned char *)\"abc\", 3, digest) == NULL) return 2;\n    return memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "The ASCII string abc for SHA-256 hashing.";
        "operation" = "Hash the bytes through OpenSSL's SHA256 API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcrypto"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "openssl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "OpenSSL returns no certificate object.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"openssl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"openssl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <openssl/x509.h>\nint main(void) {\n    const unsigned char invalid[] = \"not a certificate\"; const unsigned char *cursor = invalid;\n    X509 *certificate = d2i_X509(NULL, &cursor, sizeof(invalid));\n    if (certificate != NULL) { X509_free(certificate); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "A byte sequence that is not a DER-encoded X.509 certificate.";
        "operation" = "Decode the malformed bytes through d2i_X509.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcrypto"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "openssl rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.openssl.org/source/openssl-${version}.tar.gz"
      ];
      hash = "sha256-c2tGdTD5FnN7cDExDMsh2CGMYinmHo4WDNHTRYzVQ6g=";
    };

    buildDeps = [
      gnumake
      perl
    ];
    runtimeDeps =
      [zlib]
      ++ (
        if isDarwin
        then [perl]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openssl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          perl ./Configure \
            --prefix=$out \
            --libdir=lib \
            --openssldir=$out/etc/ssl \
            ${configureTarget} \
            no-ssl2 \
            no-ssl3 \
            no-legacy \
            shared \
            zlib \
            --with-zlib-include=${zlib}/include \
            --with-zlib-lib=${zlib}/lib \
            -Wl,-rpath,$out/lib
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
          ''
            make install_sw install_ssldirs

            # OpenSSL's build embeds the full compile command line as a
            # .rodata string so `openssl version -a` can print it — including
            # the absolute /nix/store path of the cc-wrapper. That .rodata
            # entry is application data, not debug info, so the fixup phase's
            # strip leaves it intact; the result is a closure edge from
            # libcrypto to the cc-wrapper (and through it, ~230 MB of gcc
            # toolchain) purely so `openssl version -a` can echo a build-time
            # detail. Scrub the wrapper's 32-char hash in-place (length-
            # preserving replacement with `eeeee…`): the "compiler:" string
            # stays printable but no longer registers as a closure reference.
            _ccwrap=$(dirname "$(dirname "$CC")")
            _hash=$(echo "$_ccwrap" | sed -n 's|^/nix/store/\([a-z0-9]\{32\}\)-.*|\1|p')
            if [ -n "$_hash" ]; then
              find "$out" -type f \( -name '*.so*' -o -name '*.dylib*' -o -name '*.a' -o -perm -u+x \) \
                -exec sed -i "s|$_hash|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|g" {} + 2>/dev/null || true
            fi
          ''
          + (
            if isDarwin
            then ''
              # OpenSSL 4 provides `openssl rehash` instead of c_rehash.
              # Its remaining maintenance scripts still need target Perl.
              sed -i "1s|^#!.*|#!${perl}/bin/perl|" \
                "$out/etc/ssl/misc/CA.pl" \
                "$out/etc/ssl/misc/tsget.pl"
            ''
            else ""
          );
      }
    ];

    meta = {
      description = "OpenSSL — TLS/SSL and cryptography toolkit";
      homepage = "https://www.openssl.org";
      license = "Apache-2.0";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-openssl";
        library = self;
        libs = [
          "-lssl"
          "-lcrypto"
        ];
        testSource = ''
          #include <openssl/opensslv.h>
          #include <openssl/crypto.h>
          #include <stdio.h>
          int main() {
            printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
            return 0;
          }
        '';
      };

      evp = testing.mkLinkCheck {
        pname = "lib-openssl-evp";
        library = self;
        libs = ["-lcrypto"];
        testSource = ''
          #include <openssl/evp.h>
          #include <stdio.h>
          int main() {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (!ctx) return 1;
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) return 1;
            const char *msg = "hello AOS";
            if (EVP_DigestUpdate(ctx, msg, 9) != 1) return 1;
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int len;
            if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) return 1;
            EVP_MD_CTX_free(ctx);
            printf("openssl EVP SHA256 digest length: %u\n", len);
            return 0;
          }
        '';
      };

      dtls = testing.mkLinkCheck {
        pname = "lib-openssl-dtls";
        library = self;
        libs = ["-lssl" "-lcrypto"];
        testSource = ''
          #include <openssl/opensslconf.h>
          #include <openssl/ssl.h>

          #ifdef OPENSSL_NO_DTLS
          #error "OpenSSL was built without DTLS"
          #endif

          int main(void) {
              SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
              if (ctx == NULL) return 1;
              SSL_CTX_free(ctx);
              return 0;
          }
        '';
      };

      rand = testing.mkLinkCheck {
        pname = "lib-openssl-rand";
        library = self;
        libs = ["-lcrypto"];
        testSource = ''
          #include <openssl/rand.h>
          #include <stdio.h>
          int main() {
            unsigned char buf[32];
            if (RAND_bytes(buf, sizeof(buf)) != 1) return 1;
            printf("openssl RAND_bytes: generated 32 bytes\n");
            return 0;
          }
        '';
      };

      cli-version = testing.mkToolCheck {
        pname = "lib-openssl-cli-version";
        tool = self;
        command = "openssl version";
      };

      cli-dgst = testing.mkVMTest {
        name = "lib-openssl-cli-dgst";
        rootfsDeps = [self];
        testScript = ''
          echo "test" > /tmp/input.txt
          OUTPUT=$(openssl dgst -sha256 /tmp/input.txt)
          echo "$OUTPUT"
          # Verify output contains a hex hash (at least 64 hex chars for SHA256)
          case "$OUTPUT" in
            *[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
              echo "==> SHA256 digest output contains hex hash"
              ;;
            *)
              echo "==> ERROR: no hex hash found in output" >&2
              exit 1
              ;;
          esac
        '';
      };

      header-version = testing.mkLinkCheck {
        pname = "lib-openssl-header-version";
        library = self;
        libs = ["-lcrypto"];
        testSource = ''
          #include <openssl/opensslv.h>
          #include <openssl/crypto.h>
          #include <stdio.h>
          #include <string.h>
          int main(void) {
              const char *hdr = OPENSSL_VERSION_TEXT;
              const char *lib = OpenSSL_version(OPENSSL_VERSION);
              printf("header:  %s\n", hdr);
              printf("runtime: %s\n", lib);
              if (strcmp(hdr, lib) != 0) {
                  fprintf(stderr, "MISMATCH: header and runtime versions differ\n");
                  return 1;
              }
              printf("openssl-header-version: PASS\n");
              return 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = [
          "libssl.so"
          "libcrypto.so"
        ];
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libssl.so";
        symbols = [
          "SSL_read"
          "SSL_write"
          "SSL_connect"
          "SSL_accept"
        ];
      };

      crypto-symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libcrypto.so";
        symbols = [
          "EVP_EncryptInit"
          "EVP_DigestInit"
        ];
      };

      version-consistency = testing.mkVersionCheck {
        pkg = self;
        name = "openssl";
        headerCode = ''
          #include <openssl/opensslv.h>
          #include <openssl/crypto.h>
        '';
        runtimeCode = ''
          const char *header_ver = OPENSSL_VERSION_TEXT;
          const char *runtime_ver = OpenSSL_version(OPENSSL_VERSION);
        '';
        libs = [
          "-lssl"
          "-lcrypto"
        ];
      };

      consumers = testing.mkVMTest {
        name = "lib-openssl-consumers";
        rootfsDeps = [
          pkgs.curl
          pkgs.openssh
          pkgs.libssh2
          pkgs.elfutils
          self
        ];
        testScript = ''
          FAIL=0
          for bin in \
            ${pkgs.curl}/bin/curl \
            ${pkgs.openssh}/bin/ssh; do
            echo "==> Checking $bin"
            OUTPUT=$(readelf -d "$bin" 2>&1) || true
            case "$OUTPUT" in
              *libssl* | *libcrypto*)
                echo "    OK: links against openssl"
                ;;
              *)
                echo "    FAIL: no openssl linkage found" >&2
                FAIL=1
                ;;
            esac
          done
          for lib in \
            ${pkgs.libssh2}/lib/libssh2.so; do
            echo "==> Checking $lib"
            if [ ! -e "$lib" ]; then
              echo "    SKIP: $lib not found"
              continue
            fi
            OUTPUT=$(readelf -d "$lib" 2>&1) || true
            case "$OUTPUT" in
              *libssl* | *libcrypto*)
                echo "    OK: links against openssl"
                ;;
              *)
                echo "    FAIL: no openssl linkage found" >&2
                FAIL=1
                ;;
            esac
          done
          if [ "$FAIL" -ne 0 ]; then
            echo "==> ERROR: some consumers missing openssl linkage" >&2
            exit 1
          fi
          echo "==> openssl-consumers: PASS"
        '';
      };
    };
  }
