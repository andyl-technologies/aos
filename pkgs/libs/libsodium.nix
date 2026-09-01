##! libsodium — Modern cryptography library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.21";
in
  mkDerivation {
    pname = "libsodium";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/jedisct1/libsodium/archive/refs/tags/${version}-RELEASE.tar.gz"
        "https://download.libsodium.org/libsodium/releases/old/libsodium-${version}-RELEASE.tar.gz"
      ];
      hash = "sha256-QuDKlPquyQH0++2oSxuUsY9TCcNgxmNFz1Knq1FbJFs=";
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
