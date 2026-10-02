##! libsodium — Modern cryptography library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.22";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libsodium";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The digest matches the published SHA-256 test value.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libsodium primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libsodium rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <sodium.h>\nint main(void) {\n    static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};\n    unsigned char digest[32];\n    if (sodium_init() < 0) return 2;\n    crypto_hash_sha256(digest, (const unsigned char *)\"abc\", 3);\n    return sodium_memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "The ASCII string abc for SHA-256 hashing.";
        "operation" = "Hash the message through crypto_hash_sha256.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsodium"
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
              "exact" = "libsodium primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libsodium returns failure instead of accepting the password.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libsodium primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libsodium rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <sodium.h>\nint main(void) {\n    if (sodium_init() < 0) return 2;\n    if (crypto_pwhash_str_verify(\"not-a-password-hash\", \"secret\", 6) == 0) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A password-hash string outside libsodium's encoded format.";
        "operation" = "Verify the malformed hash with crypto_pwhash_str_verify.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsodium"
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
              "exact" = "libsodium rejected invalid input\n";
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
        "https://github.com/jedisct1/libsodium/archive/refs/tags/${version}-RELEASE.tar.gz"
        "https://download.libsodium.org/libsodium/releases/old/libsodium-${version}-RELEASE.tar.gz"
      ];
      hash = "sha256-WDi7DD2mFIwk6+Ux0e0Sl96ah66nfUJrzZnyieaBYxw=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libsodium-${version}-RELEASE
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static
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
        '';
      }
    ];

    meta = {
      description = "libsodium — modern, easy-to-use cryptography library";
      homepage = "https://libsodium.org";
      license = "ISC";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libsodium.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-libsodium";
        library = self;
        libs = ["-lsodium"];
        testSource = ''
          #include <sodium.h>
          #include <stdio.h>
          int main() {
            if (sodium_init() < 0) return 1;
            printf("libsodium version: %s\n", sodium_version_string());
            return 0;
          }
        '';
      };

      roundtrip = testing.mkLinkCheck {
        pname = "lib-libsodium-roundtrip";
        library = self;
        libs = ["-lsodium"];
        testSource = ''
          #include <sodium.h>
          #include <string.h>
          #include <stdio.h>
          int main(void) {
              if (sodium_init() < 0) return 1;
              unsigned char key[crypto_secretbox_KEYBYTES];
              unsigned char nonce[crypto_secretbox_NONCEBYTES];
              crypto_secretbox_keygen(key);
              randombytes_buf(nonce, sizeof nonce);
              const char *msg = "hello AOS secretbox";
              size_t msg_len = strlen(msg);
              size_t ct_len = crypto_secretbox_MACBYTES + msg_len;
              unsigned char ciphertext[256];
              if (crypto_secretbox_easy(ciphertext, (const unsigned char *)msg,
                                        msg_len, nonce, key) != 0) return 1;
              unsigned char decrypted[256];
              if (crypto_secretbox_open_easy(decrypted, ciphertext, ct_len,
                                             nonce, key) != 0) return 1;
              if (memcmp(decrypted, msg, msg_len) != 0) return 1;
              printf("libsodium-roundtrip: PASS\n");
              return 0;
          }
        '';
      };
    };
  }
