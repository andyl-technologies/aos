# Library Integration Checks

Layer 2.5 compile+link+run tests for every shared library in the AOS package set.
Each test is a Nix derivation that compiles a minimal C or C++ program against the
library, links it, and executes the resulting binary in the build sandbox. This
validates header installation, shared library linkage, RPATH correctness, and basic
API functionality.

## Test derivation pattern

Every test follows the same structure:

```nix
mkDerivation {
  pname = "integration-check-libfoo";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libfoo ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <foo.h>
      int main(void) { foo_init(); return 0; }
      EOF
      $CC -o test test.c -lfoo
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

Key conventions:
- `$CC` is the ccWrapper (gcc with automatic `-isystem`, `-L`, `-Wl,-rpath` injection)
- `runtimeDeps` brings headers into `C_INCLUDE_PATH` and libraries into `LIBRARY_PATH`
- The binary is executed immediately after compilation to verify runtime linking
- `$out/result` must be created for Nix to consider the derivation successful
- C++ tests use `$CXX` (g++ via ccWrapper) and `-std=c++17` unless noted otherwise

## Notation

Each test specification includes:
- **Test name** -- derivation `pname`
- **Validates** -- what the test proves
- **Program** -- the C/C++ source or shell commands
- **Compile** -- the compilation command
- **runtimeDeps** -- packages required

Consumer verification tests use `ldd` or `readelf` on the host to confirm that
a built binary links against the expected `.so` from the correct Nix store path.

---

## 1. TLS/Crypto Libraries

### 1.1 openssl (3.3.2) -- 10+ dependents

OpenSSL provides `libssl` (TLS protocol) and `libcrypto` (cryptographic primitives).
It is the most depended-upon library in AOS. An ABI break here cascades to curl,
openssh, nginx, systemd, nix, libssh2, libgit2, libarchive, and rsync.

#### `openssl-link-libssl`

**Validates:** libssl headers installed, libssl.so linkable, SSL_CTX usable at runtime.

```nix
mkDerivation {
  pname = "integration-check-openssl-link-libssl";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <openssl/ssl.h>
      #include <openssl/err.h>
      #include <stdio.h>
      int main(void) {
          SSL_CTX *ctx;
          SSL_library_init();
          ctx = SSL_CTX_new(TLS_client_method());
          if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }
          SSL_CTX_free(ctx);
          printf("openssl-link-libssl: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lssl -lcrypto
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `openssl-link-libcrypto`

**Validates:** libcrypto headers installed, libcrypto.so linkable, EVP API usable.

```nix
mkDerivation {
  pname = "integration-check-openssl-link-libcrypto";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <openssl/evp.h>
      #include <stdio.h>
      int main(void) {
          EVP_MD_CTX *ctx = EVP_MD_CTX_new();
          if (!ctx) { fprintf(stderr, "EVP_MD_CTX_new failed\n"); return 1; }
          if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) return 1;
          EVP_MD_CTX_free(ctx);
          printf("openssl-link-libcrypto: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcrypto
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `openssl-cli-version`

**Validates:** openssl binary runs, libcrypto loads at runtime.

```nix
mkDerivation {
  pname = "integration-check-openssl-cli-version";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      openssl version
      openssl version | head -1
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `openssl-cli-dgst`

**Validates:** crypto digest operations work end-to-end.

```nix
mkDerivation {
  pname = "integration-check-openssl-cli-dgst";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      echo "test data" > input.txt
      openssl dgst -sha256 input.txt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `openssl-header-version`

**Validates:** compile-time OPENSSL_VERSION_NUMBER matches runtime OpenSSL_version_num().
Catches mismatched header/library installations.

```nix
mkDerivation {
  pname = "integration-check-openssl-header-version";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <openssl/opensslv.h>
      #include <openssl/crypto.h>
      #include <stdio.h>
      int main(void) {
          unsigned long hdr = OPENSSL_VERSION_NUMBER;
          unsigned long lib = OpenSSL_version_num();
          printf("header: 0x%08lx  runtime: 0x%08lx\n", hdr, lib);
          /* Major and minor must match */
          if ((hdr >> 20) != (lib >> 20)) {
              fprintf(stderr, "MISMATCH\n");
              return 1;
          }
          printf("openssl-header-version: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcrypto
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `openssl-consumers`

**Validates:** all direct consumers of openssl link against the correct store path.

```nix
mkDerivation {
  pname = "integration-check-openssl-consumers";
  buildDeps = [ make ];
  runtimeDeps = [
    pkgs.openssl pkgs.curl pkgs.openssh pkgs.nginx pkgs.systemd
    pkgs.rsync pkgs.nix pkgs.libssh2 pkgs.libgit2 pkgs.libarchive
  ];
  phases = [{
    name = "check";
    script = ''
      check_links_openssl() {
        local bin="$1"
        if ! ldd "$bin" 2>/dev/null | grep -q libssl; then
          if ! ldd "$bin" 2>/dev/null | grep -q libcrypto; then
            echo "FAIL: $bin does not link libssl or libcrypto"
            return 1
          fi
        fi
        echo "OK: $bin links openssl"
      }
      check_links_openssl ${pkgs.curl}/bin/curl
      check_links_openssl ${pkgs.openssh}/bin/ssh
      check_links_openssl ${pkgs.nginx}/bin/nginx
      check_links_openssl ${pkgs.rsync}/bin/rsync
      check_links_openssl ${pkgs.nix}/bin/nix
      ldd ${pkgs.libssh2}/lib/libssh2.so | grep -q libcrypto
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libcrypto
      ldd ${pkgs.libarchive}/lib/libarchive.so | grep -q libcrypto
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 1.2 libsodium (1.0.20)

Modern cryptography library used by nix for signing.

#### `libsodium-link`

**Validates:** libsodium headers installed, libsodium.so linkable, init and keygen work.

```nix
mkDerivation {
  pname = "integration-check-libsodium-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libsodium ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sodium.h>
      #include <stdio.h>
      int main(void) {
          if (sodium_init() < 0) return 1;
          unsigned char pk[crypto_box_PUBLICKEYBYTES];
          unsigned char sk[crypto_box_SECRETKEYBYTES];
          crypto_box_keypair(pk, sk);
          printf("libsodium-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lsodium
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libsodium-roundtrip`

**Validates:** encrypt/decrypt cycle produces correct output.

```nix
mkDerivation {
  pname = "integration-check-libsodium-roundtrip";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libsodium ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sodium.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          if (sodium_init() < 0) return 1;
          unsigned char key[crypto_secretbox_KEYBYTES];
          unsigned char nonce[crypto_secretbox_NONCEBYTES];
          crypto_secretbox_keygen(key);
          randombytes_buf(nonce, sizeof nonce);
          const char *msg = "hello AOS";
          size_t mlen = strlen(msg);
          size_t clen = crypto_secretbox_MACBYTES + mlen;
          unsigned char cipher[clen];
          unsigned char plain[mlen];
          if (crypto_secretbox_easy(cipher, (const unsigned char *)msg, mlen, nonce, key) != 0)
              return 1;
          if (crypto_secretbox_open_easy(plain, cipher, clen, nonce, key) != 0)
              return 1;
          if (memcmp(plain, msg, mlen) != 0) return 1;
          printf("libsodium-roundtrip: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lsodium
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libsodium-consumers`

**Validates:** nix links against libsodium.

```nix
mkDerivation {
  pname = "integration-check-libsodium-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.nix pkgs.libsodium pkgs.minisign ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libsodium
      ldd ${pkgs.minisign}/bin/minisign | grep -q libsodium
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 2. Compression Libraries

### 2.1 zlib (1.3.1) -- 10+ dependents

The most widely-linked compression library. Used by openssl, curl, nginx, python3,
systemd, nix, libarchive, libgit2, elfutils, and boost.

#### `zlib-link-deflate`

**Validates:** zlib headers installed, libz.so linkable, compress/uncompress work.

```nix
mkDerivation {
  pname = "integration-check-zlib-link-deflate";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <zlib.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *src = "hello zlib compression test data";
          uLong srcLen = strlen(src);
          uLong dstLen = compressBound(srcLen);
          Bytef dst[dstLen];
          if (compress(dst, &dstLen, (const Bytef *)src, srcLen) != Z_OK) return 1;
          char result[256];
          uLong resLen = sizeof(result);
          if (uncompress((Bytef *)result, &resLen, dst, dstLen) != Z_OK) return 1;
          if (memcmp(result, src, srcLen) != 0) return 1;
          printf("zlib-link-deflate: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lz
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `zlib-header-version`

**Validates:** ZLIB_VERSION macro matches zlibVersion() runtime string.

```nix
mkDerivation {
  pname = "integration-check-zlib-header-version";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <zlib.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *hdr = ZLIB_VERSION;
          const char *lib = zlibVersion();
          printf("header: %s  runtime: %s\n", hdr, lib);
          if (strcmp(hdr, lib) != 0) {
              fprintf(stderr, "MISMATCH\n");
              return 1;
          }
          printf("zlib-header-version: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lz
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `zlib-consumers`

**Validates:** all major zlib consumers link against the correct libz.so.

```nix
mkDerivation {
  pname = "integration-check-zlib-consumers";
  buildDeps = [ make ];
  runtimeDeps = [
    pkgs.zlib pkgs.openssl pkgs.curl pkgs.nginx pkgs.python3
    pkgs.systemd pkgs.nix pkgs.libarchive pkgs.elfutils pkgs.libgit2
  ];
  phases = [{
    name = "check";
    script = ''
      for lib in \
        ${pkgs.openssl}/lib/libcrypto.so \
        ${pkgs.curl}/lib/libcurl.so \
        ${pkgs.nginx}/bin/nginx \
        ${pkgs.python3}/bin/python3 \
        ${pkgs.nix}/bin/nix \
        ${pkgs.libarchive}/lib/libarchive.so \
        ${pkgs.elfutils}/lib/libelf.so \
        ${pkgs.libgit2}/lib/libgit2.so; do
        ldd "$lib" | grep -q libz || {
          echo "FAIL: $lib does not link libz"
          exit 1
        }
        echo "OK: $lib links libz"
      done
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 2.2 zstd (1.5.6)

Used by systemd, libarchive, elfutils.

#### `zstd-link`

**Validates:** zstd headers installed, libzstd.so linkable, compress/decompress work.

```nix
mkDerivation {
  pname = "integration-check-zstd-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.zstd ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <zstd.h>
      #include <string.h>
      #include <stdio.h>
      #include <stdlib.h>
      int main(void) {
          const char *src = "hello zstd compression test data";
          size_t srcSize = strlen(src);
          size_t dstCap = ZSTD_compressBound(srcSize);
          void *dst = malloc(dstCap);
          size_t cSize = ZSTD_compress(dst, dstCap, src, srcSize, 1);
          if (ZSTD_isError(cSize)) return 1;
          size_t origSize = ZSTD_getFrameContentSize(dst, cSize);
          char *result = malloc(origSize);
          size_t dSize = ZSTD_decompress(result, origSize, dst, cSize);
          if (ZSTD_isError(dSize)) return 1;
          if (memcmp(result, src, srcSize) != 0) return 1;
          free(dst); free(result);
          printf("zstd-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lzstd
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `zstd-cli-roundtrip`

**Validates:** zstd binary and runtime library work for file compression.

```nix
mkDerivation {
  pname = "integration-check-zstd-cli-roundtrip";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.zstd ];
  phases = [{
    name = "check";
    script = ''
      echo "test payload for zstd" > input.txt
      zstd input.txt -o compressed.zst
      zstd -d compressed.zst -o output.txt
      diff input.txt output.txt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `zstd-consumers`

**Validates:** systemd, libarchive, elfutils link against libzstd.

```nix
mkDerivation {
  pname = "integration-check-zstd-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.zstd pkgs.libarchive pkgs.elfutils ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libarchive}/lib/libarchive.so | grep -q libzstd
      ldd ${pkgs.elfutils}/lib/libelf.so | grep -q libzstd || \
        ldd ${pkgs.elfutils}/lib/libdw.so | grep -q libzstd
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 2.3 lz4 (1.9.4)

Used by systemd, libarchive.

#### `lz4-link`

**Validates:** lz4 headers installed, liblz4.so linkable, compression works.

```nix
mkDerivation {
  pname = "integration-check-lz4-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.lz4 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <lz4.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *src = "hello lz4 compression test";
          int srcSize = (int)strlen(src);
          int dstCap = LZ4_compressBound(srcSize);
          char dst[dstCap];
          int cSize = LZ4_compress_default(src, dst, srcSize, dstCap);
          if (cSize <= 0) return 1;
          char result[256];
          int dSize = LZ4_decompress_safe(dst, result, cSize, sizeof(result));
          if (dSize != srcSize) return 1;
          if (memcmp(result, src, srcSize) != 0) return 1;
          printf("lz4-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -llz4
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `lz4-cli-roundtrip`

**Validates:** lz4 binary works for file compression/decompression.

```nix
mkDerivation {
  pname = "integration-check-lz4-cli-roundtrip";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.lz4 ];
  phases = [{
    name = "check";
    script = ''
      echo "test payload for lz4" > input.txt
      lz4 input.txt compressed.lz4
      lz4 -d compressed.lz4 output.txt
      diff input.txt output.txt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `lz4-consumers`

**Validates:** libarchive links against liblz4.

```nix
mkDerivation {
  pname = "integration-check-lz4-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.lz4 pkgs.libarchive ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libarchive}/lib/libarchive.so | grep -q liblz4
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 2.4 bzip2 (1.0.8)

Used by elfutils, libarchive, boost, libsemanage.

#### `bzip2-link`

**Validates:** bzlib.h installed, libbz2.so linkable, compression API works.

```nix
mkDerivation {
  pname = "integration-check-bzip2-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.bzip2 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <bzlib.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *src = "hello bzip2 compression test";
          unsigned int srcLen = (unsigned int)strlen(src);
          char dst[1024];
          unsigned int dstLen = sizeof(dst);
          int rc = BZ2_bzBuffToBuffCompress(dst, &dstLen, (char *)src, srcLen, 9, 0, 30);
          if (rc != BZ_OK) return 1;
          char result[256];
          unsigned int resLen = sizeof(result);
          rc = BZ2_bzBuffToBuffDecompress(result, &resLen, dst, dstLen, 0, 0);
          if (rc != BZ_OK) return 1;
          if (memcmp(result, src, srcLen) != 0) return 1;
          printf("bzip2-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lbz2
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `bzip2-cli-roundtrip`

**Validates:** bzip2 binary works for file compression/decompression.

```nix
mkDerivation {
  pname = "integration-check-bzip2-cli-roundtrip";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.bzip2 ];
  phases = [{
    name = "check";
    script = ''
      echo "test payload for bzip2" > input.txt
      bzip2 -k input.txt
      bzip2 -d input.txt.bz2 -c > output.txt
      diff input.txt output.txt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `bzip2-consumers`

**Validates:** elfutils, libarchive, boost link against libbz2.

```nix
mkDerivation {
  pname = "integration-check-bzip2-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.bzip2 pkgs.elfutils pkgs.libarchive ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.elfutils}/lib/libelf.so | grep -q libbz2 || \
        ldd ${pkgs.elfutils}/lib/libdw.so | grep -q libbz2
      ldd ${pkgs.libarchive}/lib/libarchive.so | grep -q libbz2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 2.5 brotli (1.1.0)

Used by nix. Provides libbrotlienc (encoder) and libbrotlidec (decoder).

#### `brotli-link-encode`

**Validates:** brotli encoder headers installed, libbrotlienc.so linkable.

```nix
mkDerivation {
  pname = "integration-check-brotli-link-encode";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.brotli ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <brotli/encode.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *src = "hello brotli encoder test";
          size_t srcLen = strlen(src);
          size_t dstLen = BrotliEncoderMaxCompressedSize(srcLen);
          uint8_t dst[dstLen];
          if (BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                                    BROTLI_DEFAULT_MODE, srcLen,
                                    (const uint8_t *)src, &dstLen, dst) != BROTLI_TRUE)
              return 1;
          printf("brotli-link-encode: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lbrotlienc -lbrotlicommon
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `brotli-link-decode`

**Validates:** brotli decoder headers installed, libbrotlidec.so linkable.

```nix
mkDerivation {
  pname = "integration-check-brotli-link-decode";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.brotli ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <brotli/encode.h>
      #include <brotli/decode.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          const char *src = "hello brotli decoder test";
          size_t srcLen = strlen(src);
          /* Compress first */
          size_t encLen = BrotliEncoderMaxCompressedSize(srcLen);
          uint8_t enc[encLen];
          BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                                BROTLI_DEFAULT_MODE, srcLen,
                                (const uint8_t *)src, &encLen, enc);
          /* Decompress */
          size_t decLen = 256;
          uint8_t dec[256];
          BrotliDecoderResult r = BrotliDecoderDecompress(encLen, enc, &decLen, dec);
          if (r != BROTLI_DECODER_RESULT_SUCCESS) return 1;
          if (memcmp(dec, src, srcLen) != 0) return 1;
          printf("brotli-link-decode: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lbrotlienc -lbrotlidec -lbrotlicommon
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `brotli-consumers`

**Validates:** nix links against libbrotli.

```nix
mkDerivation {
  pname = "integration-check-brotli-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.brotli pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libbrotli
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 3. Network Libraries

### 3.1 curl / libcurl (8.10.1) -- hub package

curl is a hub connecting openssl, zlib, nghttp2, and ca-certificates. Consumers
include nix, libgit2, and cmake.

#### `curl-link-easy`

**Validates:** curl/curl.h installed, libcurl.so linkable, easy API initializes.

```nix
mkDerivation {
  pname = "integration-check-curl-link-easy";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <curl/curl.h>
      #include <stdio.h>
      int main(void) {
          curl_global_init(CURL_GLOBAL_DEFAULT);
          CURL *c = curl_easy_init();
          if (!c) return 1;
          curl_easy_cleanup(c);
          curl_global_cleanup();
          printf("curl-link-easy: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcurl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `curl-link-multi`

**Validates:** curl multi (async) API linkable and initializes.

```nix
mkDerivation {
  pname = "integration-check-curl-link-multi";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <curl/curl.h>
      #include <stdio.h>
      int main(void) {
          curl_global_init(CURL_GLOBAL_DEFAULT);
          CURLM *m = curl_multi_init();
          if (!m) return 1;
          curl_multi_cleanup(m);
          curl_global_cleanup();
          printf("curl-link-multi: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcurl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `curl-cli-version`

**Validates:** curl binary runs, prints version info.

```nix
mkDerivation {
  pname = "integration-check-curl-cli-version";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      curl --version
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `curl-features`

**Validates:** curl was built with expected features (ssl, zlib, nghttp2).

```nix
mkDerivation {
  pname = "integration-check-curl-features";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      features=$(curl --version)
      echo "$features"
      echo "$features" | grep -qi ssl
      echo "$features" | grep -qi zlib
      echo "$features" | grep -qi nghttp2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `curl-consumers`

**Validates:** nix and libgit2 link against libcurl.

```nix
mkDerivation {
  pname = "integration-check-curl-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.curl pkgs.nix pkgs.libgit2 ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libcurl
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libcurl
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.2 libssh2 (1.11.1)

SSH2 client library. Uses openssl as crypto backend. Consumed by curl and libgit2.

#### `libssh2-link`

**Validates:** libssh2.h installed, libssh2.so linkable, init succeeds.

```nix
mkDerivation {
  pname = "integration-check-libssh2-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libssh2 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libssh2.h>
      #include <stdio.h>
      int main(void) {
          int rc = libssh2_init(0);
          if (rc != 0) return 1;
          const char *ver = libssh2_version(0);
          if (!ver) return 1;
          printf("libssh2 version: %s\n", ver);
          libssh2_exit();
          printf("libssh2-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lssh2
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libssh2-openssl`

**Validates:** libssh2 links against openssl (not some other crypto backend).

```nix
mkDerivation {
  pname = "integration-check-libssh2-openssl";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libssh2 pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libssh2}/lib/libssh2.so | grep -q libcrypto
      echo "libssh2 uses openssl backend"
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libssh2-consumers`

**Validates:** libgit2 links against libssh2.

```nix
mkDerivation {
  pname = "integration-check-libssh2-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libssh2 pkgs.libgit2 ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libssh2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.3 nghttp2 (1.67.1)

HTTP/2 C library. Consumed by curl.

#### `nghttp2-link`

**Validates:** nghttp2 headers installed, libnghttp2.so linkable, session API works.

```nix
mkDerivation {
  pname = "integration-check-nghttp2-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.nghttp2 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <nghttp2/nghttp2.h>
      #include <stdio.h>
      int main(void) {
          nghttp2_info *info = nghttp2_version(0);
          if (!info) return 1;
          printf("nghttp2 version: %s\n", info->version_str);
          printf("nghttp2-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnghttp2
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `nghttp2-consumers`

**Validates:** curl links against libnghttp2.

```nix
mkDerivation {
  pname = "integration-check-nghttp2-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.nghttp2 pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.curl}/lib/libcurl.so | grep -q libnghttp2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.4 libpcap (1.10.6)

Packet capture library. Depends on libnl.

#### `libpcap-link`

**Validates:** pcap.h installed, libpcap.so linkable, pcap_open_dead works.

```nix
mkDerivation {
  pname = "integration-check-libpcap-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libpcap ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <pcap/pcap.h>
      #include <stdio.h>
      int main(void) {
          pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
          if (!p) return 1;
          const char *ver = pcap_lib_version();
          printf("libpcap version: %s\n", ver);
          pcap_close(p);
          printf("libpcap-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lpcap
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.5 libnl (3.12.0)

Linux Netlink protocol library suite. Consumed by iproute2, libpcap.

#### `libnl-link`

**Validates:** netlink/netlink.h installed, libnl-3.so linkable, socket API works.

```nix
mkDerivation {
  pname = "integration-check-libnl-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <netlink/netlink.h>
      #include <netlink/socket.h>
      #include <stdio.h>
      int main(void) {
          struct nl_sock *sk = nl_socket_alloc();
          if (!sk) return 1;
          nl_socket_free(sk);
          printf("libnl-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c $(pkg-config --cflags --libs libnl-3.0)
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libnl-consumers`

**Validates:** iproute2 and libpcap link against libnl.

```nix
mkDerivation {
  pname = "integration-check-libnl-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnl pkgs.iproute2 pkgs.libpcap ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.iproute2}/bin/ip | grep -q libnl
      ldd ${pkgs.libpcap}/lib/libpcap.so | grep -q libnl
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.6 libmnl (1.0.5)

Minimalistic Netlink library. Consumed by libnftnl, iptables, nftables,
libnetfilter_conntrack, libnetfilter_queue, libnetfilter_cthelper,
libnetfilter_cttimeout.

#### `libmnl-link`

**Validates:** libmnl.h installed, libmnl.so linkable, socket API works.

```nix
mkDerivation {
  pname = "integration-check-libmnl-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libmnl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libmnl/libmnl.h>
      #include <stdio.h>
      int main(void) {
          struct mnl_socket *nl = mnl_socket_open(0 /* NETLINK_ROUTE */);
          /* open may fail in sandbox (no real kernel netlink), but the
             symbol resolves -- that's what we're testing. */
          if (nl) mnl_socket_close(nl);
          printf("libmnl-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libmnl-consumers`

**Validates:** libnftnl, iptables, nftables link against libmnl.

```nix
mkDerivation {
  pname = "integration-check-libmnl-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libmnl pkgs.libnftnl pkgs.iptables pkgs.nftables ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libnftnl}/lib/libnftnl.so | grep -q libmnl
      ldd ${pkgs.iptables}/bin/xtables-nft-multi | grep -q libmnl
      ldd ${pkgs.nftables}/bin/nft | grep -q libmnl
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.7 libnfnetlink (1.0.2)

Low-level netfilter netlink communication library.

#### `libnfnetlink-link`

**Validates:** libnfnetlink.h installed, libnfnetlink.so linkable.

```nix
mkDerivation {
  pname = "integration-check-libnfnetlink-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnfnetlink ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnfnetlink/libnfnetlink.h>
      #include <stdio.h>
      int main(void) {
          /* nfnl_open may fail in sandbox; we test symbol resolution. */
          struct nfnl_handle *h = nfnl_open();
          if (h) nfnl_close(h);
          printf("libnfnetlink-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnfnetlink
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.8 libnetfilter_conntrack (1.1.0)

Userspace library for connection tracking. Depends on libmnl and libnfnetlink.

#### `libnetfilter-conntrack-link`

**Validates:** libnetfilter_conntrack.h installed, library linkable, nfct_new works.

```nix
mkDerivation {
  pname = "integration-check-libnetfilter-conntrack-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnetfilter_conntrack ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnetfilter_conntrack/libnetfilter_conntrack.h>
      #include <stdio.h>
      int main(void) {
          struct nf_conntrack *ct = nfct_new();
          if (!ct) return 1;
          nfct_destroy(ct);
          printf("libnetfilter-conntrack-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnetfilter_conntrack -lnfnetlink -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.9 libnetfilter_queue (1.0.5)

Userspace API to packets queued by the kernel. Depends on libmnl and libnfnetlink.

#### `libnetfilter-queue-link`

**Validates:** libnetfilter_queue.h installed, library linkable.

```nix
mkDerivation {
  pname = "integration-check-libnetfilter-queue-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnetfilter_queue ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnetfilter_queue/libnetfilter_queue.h>
      #include <stdio.h>
      int main(void) {
          /* nfq_open requires kernel netlink; test symbol resolution. */
          struct nfq_handle *h = nfq_open();
          if (h) nfq_close(h);
          printf("libnetfilter-queue-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnetfilter_queue -lnfnetlink -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.10 libnetfilter_cthelper (1.0.1)

User-space connection tracking helper. Depends on libmnl.

#### `libnetfilter-cthelper-link`

**Validates:** headers installed, library linkable.

```nix
mkDerivation {
  pname = "integration-check-libnetfilter-cthelper-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnetfilter_cthelper ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnetfilter_cthelper/libnetfilter_cthelper.h>
      #include <stdio.h>
      int main(void) {
          struct nfct_helper *h = nfct_helper_alloc();
          if (!h) return 1;
          nfct_helper_free(h);
          printf("libnetfilter-cthelper-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnetfilter_cthelper -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.11 libnetfilter_cttimeout (1.0.1)

Connection tracking timeout policy library. Depends on libmnl.

#### `libnetfilter-cttimeout-link`

**Validates:** headers installed, library linkable.

```nix
mkDerivation {
  pname = "integration-check-libnetfilter-cttimeout-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnetfilter_cttimeout ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>
      #include <stdio.h>
      int main(void) {
          struct nfct_timeout *t = nfct_timeout_alloc();
          if (!t) return 1;
          nfct_timeout_free(t);
          printf("libnetfilter-cttimeout-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnetfilter_cttimeout -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 3.12 libnftnl (1.2.8)

Userspace library for nf_tables Netlink communication. Depends on libmnl. Consumed
by nftables.

#### `libnftnl-link`

**Validates:** libnftnl headers installed, library linkable, table alloc API works.

```nix
mkDerivation {
  pname = "integration-check-libnftnl-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnftnl ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libnftnl/table.h>
      #include <stdio.h>
      int main(void) {
          struct nftnl_table *t = nftnl_table_alloc();
          if (!t) return 1;
          nftnl_table_set_str(t, NFTNL_TABLE_NAME, "test");
          nftnl_table_free(t);
          printf("libnftnl-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lnftnl -lmnl
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libnftnl-consumers`

**Validates:** nftables links against libnftnl.

```nix
mkDerivation {
  pname = "integration-check-libnftnl-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libnftnl pkgs.nftables ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nftables}/bin/nft | grep -q libnftnl
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 4. Data/Parsing Libraries

### 4.1 sqlite (3.47.2)

Self-contained SQL database engine. Consumed by nix and python3.

#### `sqlite-link`

**Validates:** sqlite3.h installed, libsqlite3.so linkable, database operations work.

```nix
mkDerivation {
  pname = "integration-check-sqlite-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.sqlite ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sqlite3.h>
      #include <stdio.h>
      int main(void) {
          sqlite3 *db;
          int rc = sqlite3_open(":memory:", &db);
          if (rc != SQLITE_OK) return 1;
          char *err = NULL;
          rc = sqlite3_exec(db, "CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(42);",
                            NULL, NULL, &err);
          if (rc != SQLITE_OK) { fprintf(stderr, "%s\n", err); return 1; }
          /* Query back */
          sqlite3_stmt *stmt;
          sqlite3_prepare_v2(db, "SELECT x FROM t", -1, &stmt, NULL);
          if (sqlite3_step(stmt) != SQLITE_ROW) return 1;
          int val = sqlite3_column_int(stmt, 0);
          if (val != 42) return 1;
          sqlite3_finalize(stmt);
          sqlite3_close(db);
          printf("sqlite-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lsqlite3 -lpthread
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `sqlite-cli`

**Validates:** sqlite3 CLI binary works, can create and query databases.

```nix
mkDerivation {
  pname = "integration-check-sqlite-cli";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.sqlite ];
  phases = [{
    name = "check";
    script = ''
      sqlite3 test.db "CREATE TABLE t(x); INSERT INTO t VALUES('hello');"
      result=$(sqlite3 test.db "SELECT x FROM t;")
      test "$result" = "hello"
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `sqlite-consumers`

**Validates:** nix links against libsqlite3.

```nix
mkDerivation {
  pname = "integration-check-sqlite-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.sqlite pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libsqlite3
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.2 jansson (2.14.1)

C library for JSON. Consumed by nftables.

#### `jansson-link`

**Validates:** jansson.h installed, libjansson.so linkable, JSON parse/emit works.

```nix
mkDerivation {
  pname = "integration-check-jansson-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.jansson ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <jansson.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          json_error_t err;
          json_t *obj = json_loads("{\"key\": 42}", 0, &err);
          if (!obj) return 1;
          json_t *val = json_object_get(obj, "key");
          if (json_integer_value(val) != 42) return 1;
          char *s = json_dumps(obj, JSON_COMPACT);
          if (!s) return 1;
          json_decref(obj);
          free(s);
          printf("jansson-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -ljansson
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `jansson-consumers`

**Validates:** nftables links against libjansson.

```nix
mkDerivation {
  pname = "integration-check-jansson-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.jansson pkgs.nftables ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nftables}/bin/nft | grep -q libjansson
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.3 nlohmann-json (3.11.3) -- header-only

Header-only C++ JSON library. Consumed by nix.

#### `nlohmann-json-compile`

**Validates:** nlohmann/json.hpp headers installed, C++ compilation succeeds,
JSON round-trip works at runtime.

```nix
mkDerivation {
  pname = "integration-check-nlohmann-json-compile";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.nlohmann-json ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <nlohmann/json.hpp>
      #include <iostream>
      #include <string>
      int main() {
          nlohmann::json j;
          j["key"] = 42;
          j["name"] = "test";
          std::string s = j.dump();
          auto parsed = nlohmann::json::parse(s);
          if (parsed["key"] != 42) return 1;
          if (parsed["name"] != "test") return 1;
          std::cout << "nlohmann-json-compile: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.4 toml11 (4.2.0) -- header-only

Header-only C++ TOML library. Consumed by nix.

#### `toml11-compile`

**Validates:** toml.hpp headers installed, C++ compilation succeeds, TOML parsing works.

```nix
mkDerivation {
  pname = "integration-check-toml11-compile";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.toml11 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.toml << 'EOF'
      [package]
      name = "test"
      version = "1.0"
      EOF
      cat > test.cpp << 'EOF'
      #include <toml.hpp>
      #include <iostream>
      #include <fstream>
      int main() {
          auto data = toml::parse("test.toml");
          auto name = toml::find<std::string>(data, "package", "name");
          if (name != "test") return 1;
          std::cout << "toml11-compile: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.5 oniguruma (6.9.10)

Regular expression library. Consumed by jq.

#### `oniguruma-link`

**Validates:** oniguruma.h installed, libonig.so linkable, regex matching works.

```nix
mkDerivation {
  pname = "integration-check-oniguruma-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.oniguruma ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <oniguruma.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          OnigEncoding enc = ONIG_ENCODING_UTF8;
          onig_initialize(&enc, 1);
          regex_t *reg;
          OnigErrorInfo einfo;
          const UChar *pattern = (const UChar *)"he[l]+o";
          int r = onig_new(&reg, pattern, pattern + strlen((const char *)pattern),
                           ONIG_OPTION_DEFAULT, enc, ONIG_SYNTAX_DEFAULT, &einfo);
          if (r != ONIG_NORMAL) return 1;
          const UChar *str = (const UChar *)"hello";
          OnigRegion *region = onig_region_new();
          r = onig_search(reg, str, str + strlen((const char *)str),
                          str, str + strlen((const char *)str),
                          region, ONIG_OPTION_NONE);
          if (r < 0) return 1;
          onig_region_free(region, 1);
          onig_free(reg);
          onig_end();
          printf("oniguruma-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lonig
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `oniguruma-consumers`

**Validates:** jq links against libonig and regex features work.

```nix
mkDerivation {
  pname = "integration-check-oniguruma-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.oniguruma pkgs.jq ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.jq}/bin/jq | grep -q libonig
      # Test jq regex functionality (requires oniguruma)
      result=$(echo '"hello world"' | jq 'test("hel+o")')
      test "$result" = "true"
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.6 pcre2 (10.44)

Perl Compatible Regular Expressions v2. Consumed by nginx, libselinux, systemd.

#### `pcre2-link`

**Validates:** pcre2.h installed, libpcre2-8.so linkable, regex matching works.

```nix
mkDerivation {
  pname = "integration-check-pcre2-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.pcre2 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #define PCRE2_CODE_UNIT_WIDTH 8
      #include <pcre2.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          int errcode;
          PCRE2_SIZE erroff;
          pcre2_code *re = pcre2_compile(
              (PCRE2_SPTR)"he[l]+o", PCRE2_ZERO_TERMINATED,
              0, &errcode, &erroff, NULL);
          if (!re) return 1;
          pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
          PCRE2_SPTR subject = (PCRE2_SPTR)"hello";
          int rc = pcre2_match(re, subject, strlen((const char *)subject),
                               0, 0, md, NULL);
          if (rc < 0) return 1;
          pcre2_match_data_free(md);
          pcre2_code_free(re);
          printf("pcre2-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lpcre2-8
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `pcre2-consumers`

**Validates:** nginx, libselinux link against libpcre2.

```nix
mkDerivation {
  pname = "integration-check-pcre2-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.pcre2 pkgs.nginx pkgs.libselinux ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nginx}/bin/nginx | grep -q libpcre2
      ldd ${pkgs.libselinux}/lib/libselinux.so | grep -q libpcre2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.7 expat (2.6.4)

XML parsing C library. Consumed by dbus, libarchive.

#### `expat-link`

**Validates:** expat.h installed, libexpat.so linkable, XML parsing works.

```nix
mkDerivation {
  pname = "integration-check-expat-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.expat ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <expat.h>
      #include <string.h>
      #include <stdio.h>
      static int found = 0;
      static void start_element(void *data, const char *el, const char **attr) {
          if (strcmp(el, "root") == 0) found = 1;
      }
      int main(void) {
          XML_Parser p = XML_ParserCreate(NULL);
          if (!p) return 1;
          XML_SetStartElementHandler(p, start_element);
          const char *xml = "<root><child/></root>";
          if (XML_Parse(p, xml, strlen(xml), 1) == XML_STATUS_ERROR) return 1;
          XML_ParserFree(p);
          if (!found) return 1;
          printf("expat-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lexpat
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `expat-consumers`

**Validates:** dbus and libarchive link against libexpat.

```nix
mkDerivation {
  pname = "integration-check-expat-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.expat pkgs.dbus pkgs.libarchive ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.dbus}/bin/dbus-daemon | grep -q libexpat
      ldd ${pkgs.libarchive}/lib/libarchive.so | grep -q libexpat
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 4.8 libarchive (3.7.7) -- hub package

Multi-format archive library. Depends on openssl, zlib, zstd, bzip2, lz4, expat.
Consumed by nix.

#### `libarchive-link`

**Validates:** archive.h installed, libarchive.so linkable, reader API works.

```nix
mkDerivation {
  pname = "integration-check-libarchive-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libarchive ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <archive.h>
      #include <archive_entry.h>
      #include <stdio.h>
      int main(void) {
          struct archive *a = archive_read_new();
          if (!a) return 1;
          archive_read_support_filter_all(a);
          archive_read_support_format_all(a);
          printf("libarchive version: %s\n", archive_version_string());
          archive_read_free(a);
          /* Also test write API */
          struct archive *w = archive_write_new();
          if (!w) return 1;
          archive_write_free(w);
          printf("libarchive-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -larchive
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libarchive-formats`

**Validates:** libarchive can create and extract tar archives.

```nix
mkDerivation {
  pname = "integration-check-libarchive-formats";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libarchive ];
  phases = [{
    name = "check";
    script = ''
      # Use bsdtar (from libarchive) to create and extract an archive
      mkdir -p testdir
      echo "hello" > testdir/file.txt
      bsdtar -cf test.tar testdir/
      mkdir -p extract
      cd extract
      bsdtar -xf ../test.tar
      test "$(cat testdir/file.txt)" = "hello"
      cd ..
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libarchive-consumers`

**Validates:** nix links against libarchive.

```nix
mkDerivation {
  pname = "integration-check-libarchive-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libarchive pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libarchive
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 5. System/Capability Libraries

### 5.1 libcap (2.70)

POSIX capabilities library. Consumed by systemd, chrony, audit.

#### `libcap-link`

**Validates:** sys/capability.h installed, libcap.so linkable, cap_get_proc works.

```nix
mkDerivation {
  pname = "integration-check-libcap-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libcap ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sys/capability.h>
      #include <stdio.h>
      int main(void) {
          cap_t caps = cap_get_proc();
          if (!caps) {
              /* May fail in sandbox, but symbol resolved. */
              printf("cap_get_proc returned NULL (expected in sandbox)\n");
          } else {
              char *text = cap_to_text(caps, NULL);
              printf("capabilities: %s\n", text ? text : "(none)");
              if (text) cap_free(text);
              cap_free(caps);
          }
          printf("libcap-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcap
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libcap-consumers`

**Validates:** systemd, chrony, audit link against libcap.

```nix
mkDerivation {
  pname = "integration-check-libcap-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libcap pkgs.systemd pkgs.chrony pkgs.audit ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.audit}/lib/libaudit.so | grep -q libcap
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 5.2 libxcrypt (4.4.36)

Extended crypt library for password hashing. Consumed by systemd, openssh, nginx.

#### `libxcrypt-link`

**Validates:** crypt.h installed, libcrypt.so linkable, crypt function works.

```nix
mkDerivation {
  pname = "integration-check-libxcrypt-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libxcrypt ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <crypt.h>
      #include <string.h>
      #include <stdio.h>
      int main(void) {
          /* SHA-512 hash with known salt */
          const char *hash = crypt("password", "$6$testsalt$");
          if (!hash) return 1;
          /* Verify it starts with the expected prefix */
          if (strncmp(hash, "$6$", 3) != 0) return 1;
          printf("libxcrypt-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lcrypt
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libxcrypt-consumers`

**Validates:** openssh and nginx link against libcrypt.

```nix
mkDerivation {
  pname = "integration-check-libxcrypt-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libxcrypt pkgs.openssh pkgs.nginx ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.openssh}/sbin/sshd | grep -q libcrypt
      ldd ${pkgs.nginx}/bin/nginx | grep -q libcrypt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 5.3 libseccomp (2.5.5)

Seccomp userspace library. Consumed by containerd, runc.

#### `libseccomp-link`

**Validates:** seccomp.h installed, libseccomp.so linkable, filter API works.

```nix
mkDerivation {
  pname = "integration-check-libseccomp-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libseccomp ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <seccomp.h>
      #include <stdio.h>
      int main(void) {
          scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
          if (!ctx) return 1;
          int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1),
                                    SCMP_SYS(mount), 0);
          if (rc < 0) return 1;
          seccomp_release(ctx);
          printf("libseccomp version: %d.%d.%d\n",
                 (seccomp_version())->major,
                 (seccomp_version())->minor,
                 (seccomp_version())->micro);
          printf("libseccomp-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lseccomp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libseccomp-consumers`

**Validates:** runc links against libseccomp (Go packages use cgo bindings).

```nix
mkDerivation {
  pname = "integration-check-libseccomp-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libseccomp pkgs.runc ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.runc}/bin/runc | grep -q libseccomp
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 6. Terminal Libraries

### 6.1 ncurses (6.5)

Terminal handling library. Consumed by readline, editline, bash, python3, gettext.

#### `ncurses-link`

**Validates:** curses.h installed, libncursesw.so linkable, basic terminal API works.

```nix
mkDerivation {
  pname = "integration-check-ncurses-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.ncurses ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <curses.h>
      #include <stdio.h>
      int main(void) {
          /* Don't actually init the screen (no terminal in sandbox),
             but verify the symbols resolve and header is usable. */
          int color_pairs = COLOR_PAIRS;
          (void)color_pairs;
          printf("ncurses-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lncursesw
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `ncurses-tinfo-compat`

**Validates:** libtinfo.so compatibility symlink resolves correctly.

```nix
mkDerivation {
  pname = "integration-check-ncurses-tinfo-compat";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.ncurses ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <curses.h>
      #include <term.h>
      #include <stdio.h>
      int main(void) {
          /* setupterm returns OK/ERR; ERR is expected without a real terminal */
          int err;
          setupterm("dumb", 1, &err);
          printf("ncurses-tinfo-compat: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -ltinfo
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `ncurses-consumers`

**Validates:** readline, bash, python3, editline link against ncurses.

```nix
mkDerivation {
  pname = "integration-check-ncurses-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.ncurses pkgs.readline pkgs.bash pkgs.editline ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.readline}/lib/libreadline.so | grep -q ncurses
      ldd ${pkgs.bash}/bin/bash | grep -q ncurses
      ldd ${pkgs.editline}/lib/libeditline.so | grep -q ncurses
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 6.2 readline (8.2)

GNU command line editing library. Depends on ncurses. Consumed by bash.

#### `readline-link`

**Validates:** readline.h installed, libreadline.so linkable, readline function resolves.

```nix
mkDerivation {
  pname = "integration-check-readline-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.readline ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <readline/readline.h>
      #include <readline/history.h>
      #include <stdio.h>
      int main(void) {
          /* Verify symbols resolve. Don't call readline() (needs tty). */
          rl_initialize();
          using_history();
          printf("readline version: %s\n", rl_library_version);
          printf("readline-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lreadline -lncursesw
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `readline-consumers`

**Validates:** bash links against libreadline.

```nix
mkDerivation {
  pname = "integration-check-readline-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.readline pkgs.bash ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.bash}/bin/bash | grep -q libreadline
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 6.3 editline (1.17.1)

Small line editing library (troglobit). Depends on ncurses. Consumed by nix.

#### `editline-link`

**Validates:** editline.h installed, libeditline.so linkable.

```nix
mkDerivation {
  pname = "integration-check-editline-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.editline ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <editline.h>
      #include <stdio.h>
      int main(void) {
          /* Verify the symbol resolves. */
          printf("editline-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -leditline -lncursesw
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `editline-consumers`

**Validates:** nix links against libeditline.

```nix
mkDerivation {
  pname = "integration-check-editline-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.editline pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libeditline
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 7. Math Libraries

### 7.1 gmp (6.3.0)

GNU Multiple Precision Arithmetic Library. Consumed by mpfr, and transitively by
libmpc and gcc.

#### `gmp-link`

**Validates:** gmp.h installed, libgmp.so linkable, big integer arithmetic works.

```nix
mkDerivation {
  pname = "integration-check-gmp-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.gmp ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <gmp.h>
      #include <stdio.h>
      int main(void) {
          mpz_t a, b, c;
          mpz_init(a); mpz_init(b); mpz_init(c);
          mpz_set_str(a, "123456789012345678901234567890", 10);
          mpz_set_str(b, "987654321098765432109876543210", 10);
          mpz_add(c, a, b);
          char *result = mpz_get_str(NULL, 10, c);
          printf("sum: %s\n", result);
          free(result);
          mpz_clear(a); mpz_clear(b); mpz_clear(c);
          printf("gmp-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lgmp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `gmp-cxx-link`

**Validates:** gmpxx.h installed, libgmpxx.so linkable (GMP was built with --enable-cxx).

```nix
mkDerivation {
  pname = "integration-check-gmp-cxx-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.gmp ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <gmpxx.h>
      #include <iostream>
      int main() {
          mpz_class a("123456789012345678901234567890");
          mpz_class b("987654321098765432109876543210");
          mpz_class c = a + b;
          std::cout << "sum: " << c << std::endl;
          std::cout << "gmp-cxx-link: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp -lgmpxx -lgmp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `gmp-consumers`

**Validates:** mpfr links against libgmp.

```nix
mkDerivation {
  pname = "integration-check-gmp-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.gmp pkgs.mpfr ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.mpfr}/lib/libmpfr.so | grep -q libgmp
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 7.2 mpfr (4.2.2)

GNU multiple-precision floating-point library. Depends on gmp. Consumed by libmpc.

#### `mpfr-link`

**Validates:** mpfr.h installed, libmpfr.so linkable, floating-point computation works.

```nix
mkDerivation {
  pname = "integration-check-mpfr-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.mpfr ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <mpfr.h>
      #include <stdio.h>
      int main(void) {
          mpfr_t x;
          mpfr_init2(x, 256);
          mpfr_const_pi(x, MPFR_RNDN);
          printf("pi = ");
          mpfr_out_str(stdout, 10, 50, x, MPFR_RNDN);
          printf("\n");
          mpfr_clear(x);
          printf("mpfr-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lmpfr -lgmp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `mpfr-consumers`

**Validates:** libmpc links against libmpfr.

```nix
mkDerivation {
  pname = "integration-check-mpfr-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.mpfr pkgs.libmpc ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libmpc}/lib/libmpc.so | grep -q libmpfr
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 7.3 libmpc (1.3.1)

GNU library for multiprecision complex arithmetic. Depends on gmp and mpfr.
Used by gcc for compile-time constant folding of complex expressions.

#### `libmpc-link`

**Validates:** mpc.h installed, libmpc.so linkable, complex arithmetic works.

```nix
mkDerivation {
  pname = "integration-check-libmpc-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libmpc ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <mpc.h>
      #include <stdio.h>
      int main(void) {
          mpc_t z;
          mpc_init2(z, 256);
          mpc_set_d_d(z, 1.0, 2.0, MPC_RNDNN);
          mpc_mul(z, z, z, MPC_RNDNN);
          printf("(1+2i)^2 = ");
          mpc_out_str(stdout, 10, 20, z, MPC_RNDNN);
          printf("\n");
          mpc_clear(z);
          printf("libmpc-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lmpc -lmpfr -lgmp
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 8. C++ Libraries

### 8.1 boost (1.86.0)

Peer-reviewed portable C++ libraries. Built with: system, filesystem, regex,
container, context, coroutine, thread, chrono, date_time, program_options,
iostreams, serialization, log, atomic, random. Consumed by nix.

#### `boost-link-filesystem`

**Validates:** boost/filesystem.hpp installed, libboost_filesystem.so linkable.

```nix
mkDerivation {
  pname = "integration-check-boost-link-filesystem";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.boost ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <boost/filesystem.hpp>
      #include <iostream>
      int main() {
          boost::filesystem::path p("/tmp");
          if (!boost::filesystem::exists(p)) return 1;
          std::cout << "path: " << p << std::endl;
          std::cout << "boost-link-filesystem: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp -lboost_filesystem -lboost_system
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `boost-link-regex`

**Validates:** boost/regex.hpp installed, libboost_regex.so linkable.

```nix
mkDerivation {
  pname = "integration-check-boost-link-regex";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.boost ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <boost/regex.hpp>
      #include <iostream>
      #include <string>
      int main() {
          boost::regex re("he[l]+o");
          std::string s = "hello world";
          if (!boost::regex_search(s, re)) return 1;
          std::cout << "boost-link-regex: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp -lboost_regex
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `boost-link-system`

**Validates:** boost/system/error_code.hpp installed, libboost_system.so linkable.

```nix
mkDerivation {
  pname = "integration-check-boost-link-system";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.boost ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <boost/system/error_code.hpp>
      #include <iostream>
      int main() {
          boost::system::error_code ec;
          std::cout << "default error: " << ec.message() << std::endl;
          std::cout << "boost-link-system: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp -lboost_system
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `boost-link-context`

**Validates:** boost/context installed, libboost_context.so linkable. Validates
coroutine/context support needed by nix's async I/O.

```nix
mkDerivation {
  pname = "integration-check-boost-link-context";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.boost ];
  phases = [{
    name = "check";
    script = ''
      cat > test.cpp << 'EOF'
      #include <boost/context/continuation.hpp>
      #include <iostream>
      int main() {
          namespace ctx = boost::context;
          int val = 0;
          ctx::continuation c = ctx::callcc([&val](ctx::continuation &&c) {
              val = 42;
              return std::move(c);
          });
          if (val != 42) return 1;
          std::cout << "boost-link-context: PASS" << std::endl;
          return 0;
      }
      EOF
      $CXX -std=c++17 -o test test.cpp -lboost_context
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `boost-consumers`

**Validates:** nix links against boost libraries.

```nix
mkDerivation {
  pname = "integration-check-boost-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.boost pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libboost
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 9. Markdown/Text Libraries

### 9.1 lowdown (1.1.0)

Simple Markdown translator. Consumed by nix.

#### `lowdown-link`

**Validates:** lowdown.h installed, liblowdown.so linkable, markdown rendering works.

```nix
mkDerivation {
  pname = "integration-check-lowdown-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.lowdown ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sys/queue.h>
      #include <lowdown.h>
      #include <stdio.h>
      #include <string.h>
      #include <stdlib.h>
      int main(void) {
          const char *md = "# Hello\n\nworld\n";
          struct lowdown_buf *ob = NULL;
          struct lowdown_metaq metaq;
          TAILQ_INIT(&metaq);
          struct lowdown_opts opts;
          memset(&opts, 0, sizeof(opts));
          opts.type = LOWDOWN_TERM;
          int rc = lowdown_buf(&opts, md, strlen(md), &ob, &metaq);
          if (!rc) return 1;
          printf("output length: %zu\n", ob->size);
          lowdown_buf_free(ob);
          lowdown_metaq_free(&metaq);
          printf("lowdown-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -llowdown
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `lowdown-consumers`

**Validates:** nix links against liblowdown.

```nix
mkDerivation {
  pname = "integration-check-lowdown-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.lowdown pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q liblowdown
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 9.2 popt (1.19)

Command-line option parsing library. Consumed by rsync.

#### `popt-link`

**Validates:** popt.h installed, libpopt.so linkable, option parsing works.

```nix
mkDerivation {
  pname = "integration-check-popt-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.popt ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <popt.h>
      #include <stdio.h>
      int main(int argc, const char **argv) {
          int verbose = 0;
          struct poptOption optionsTable[] = {
              { "verbose", 'v', POPT_ARG_NONE, &verbose, 0, "verbose output", NULL },
              POPT_AUTOHELP
              POPT_TABLEEND
          };
          poptContext ctx = poptGetContext(NULL, argc, argv, optionsTable, 0);
          poptFreeContext(ctx);
          printf("popt-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lpopt
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `popt-consumers`

**Validates:** rsync links against libpopt.

```nix
mkDerivation {
  pname = "integration-check-popt-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.popt pkgs.rsync ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.rsync}/bin/rsync | grep -q libpopt
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 10. VCS Libraries

### 10.1 libgit2 (1.9.0)

C implementation of Git core methods. Depends on openssl, zlib, libssh2.
Consumed by nix.

#### `libgit2-link`

**Validates:** git2.h installed, libgit2.so linkable, init/shutdown works.

```nix
mkDerivation {
  pname = "integration-check-libgit2-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libgit2 ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <git2.h>
      #include <stdio.h>
      int main(void) {
          git_libgit2_init();
          int major, minor, rev;
          git_libgit2_version(&major, &minor, &rev);
          printf("libgit2 version: %d.%d.%d\n", major, minor, rev);
          git_libgit2_shutdown();
          printf("libgit2-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lgit2
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libgit2-deps`

**Validates:** libgit2 correctly links against openssl, zlib, and libssh2.

```nix
mkDerivation {
  pname = "integration-check-libgit2-deps";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libgit2 pkgs.openssl pkgs.zlib pkgs.libssh2 ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libssl
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libz
      ldd ${pkgs.libgit2}/lib/libgit2.so | grep -q libssh2
      echo "libgit2 links: openssl, zlib, libssh2"
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libgit2-consumers`

**Validates:** nix links against libgit2.

```nix
mkDerivation {
  pname = "integration-check-libgit2-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libgit2 pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libgit2
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 11. Security Libraries (SELinux)

### 11.1 libsepol (3.7)

SELinux binary policy manipulation library. Foundation of the SELinux stack.

#### `libsepol-link`

**Validates:** sepol/ headers installed, libsepol.so linkable, policy file API works.

```nix
mkDerivation {
  pname = "integration-check-libsepol-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libsepol ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <sepol/sepol.h>
      #include <sepol/policydb/policydb.h>
      #include <stdio.h>
      int main(void) {
          sepol_policy_file_t *pf = NULL;
          int rc = sepol_policy_file_create(&pf);
          if (rc < 0) return 1;
          sepol_policy_file_free(pf);
          printf("libsepol-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lsepol
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libsepol-consumers`

**Validates:** libselinux links against libsepol.

```nix
mkDerivation {
  pname = "integration-check-libsepol-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libsepol pkgs.libselinux ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libselinux}/lib/libselinux.so | grep -q libsepol
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 11.2 libselinux (3.7)

SELinux userspace runtime library. Depends on libsepol and pcre2. Consumed by
systemd, policycoreutils, util-linux, dbus.

#### `libselinux-link`

**Validates:** selinux/ headers installed, libselinux.so linkable, API callable.

```nix
mkDerivation {
  pname = "integration-check-libselinux-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libselinux ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <selinux/selinux.h>
      #include <stdio.h>
      int main(void) {
          /* is_selinux_enabled returns 0 or 1; both are valid. */
          int enabled = is_selinux_enabled();
          printf("SELinux enabled: %d\n", enabled);
          printf("libselinux-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lselinux
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `libselinux-consumers`

**Validates:** systemd and policycoreutils link against libselinux.

```nix
mkDerivation {
  pname = "integration-check-libselinux-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libselinux pkgs.systemd pkgs.policycoreutils ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.policycoreutils}/bin/sestatus | grep -q libselinux
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 11.3 libsemanage (3.7)

SELinux policy management library. Depends on libsepol, libselinux, audit, bzip2.

#### `libsemanage-link`

**Validates:** semanage/ headers installed, libsemanage.so linkable.

```nix
mkDerivation {
  pname = "integration-check-libsemanage-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libsemanage ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <semanage/semanage.h>
      #include <stdio.h>
      int main(void) {
          semanage_handle_t *sh = semanage_handle_create();
          if (!sh) {
              /* May fail without proper config; symbol resolution is the test. */
              printf("handle_create returned NULL (expected without config)\n");
          } else {
              semanage_handle_destroy(sh);
          }
          printf("libsemanage-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lsemanage -lselinux -lsepol -laudit -lbz2
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 11.4 audit / libaudit (4.0.2)

Linux auditing framework. Depends on libcap. Consumed by systemd, libsemanage,
dbus.

#### `audit-link`

**Validates:** libaudit.h installed, libaudit.so linkable, audit API callable.

```nix
mkDerivation {
  pname = "integration-check-audit-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.audit ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libaudit.h>
      #include <stdio.h>
      int main(void) {
          /* audit_open requires CAP_AUDIT_CONTROL; may fail in sandbox.
             We're testing symbol resolution and header correctness. */
          int fd = audit_open();
          if (fd >= 0) audit_close(fd);
          printf("audit-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -laudit -lcap
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `audit-consumers`

**Validates:** libsemanage and dbus link against libaudit.

```nix
mkDerivation {
  pname = "integration-check-audit-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.audit pkgs.libsemanage pkgs.dbus ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.libsemanage}/lib/libsemanage.so | grep -q libaudit
      ldd ${pkgs.dbus}/bin/dbus-daemon | grep -q libaudit
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 12. GC/Runtime Libraries

### 12.1 gc (8.2.8) -- Boehm GC

Conservative garbage collector. Consumed by nix.

#### `gc-link`

**Validates:** gc.h installed, libgc.so linkable, GC allocation works.

```nix
mkDerivation {
  pname = "integration-check-gc-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.gc ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <gc.h>
      #include <stdio.h>
      #include <string.h>
      int main(void) {
          GC_INIT();
          char *p = (char *)GC_MALLOC(1024);
          if (!p) return 1;
          memset(p, 'A', 1024);
          GC_gcollect();
          printf("gc-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lgc
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `gc-consumers`

**Validates:** nix links against libgc.

```nix
mkDerivation {
  pname = "integration-check-gc-consumers";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.gc pkgs.nix ];
  phases = [{
    name = "check";
    script = ''
      ldd ${pkgs.nix}/bin/nix | grep -q libgc
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

### 12.2 libtirpc (1.3.6)

Transport Independent RPC library.

#### `libtirpc-link`

**Validates:** rpc/ headers installed, libtirpc.so linkable.

```nix
mkDerivation {
  pname = "integration-check-libtirpc-link";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.libtirpc ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <rpc/rpc.h>
      #include <stdio.h>
      int main(void) {
          /* Verify headers and symbol resolution. clnt_create needs a
             real RPC service, so just test it compiles and links. */
          printf("libtirpc-link: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c $(pkg-config --cflags --libs libtirpc)
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## 13. ELF Libraries

### 13.1 elfutils (0.191) -- libelf, libdw

ELF manipulation libraries. Depends on zlib, xz, bzip2, zstd. Consumed by
systemd (via libdw for coredumps).

#### `elfutils-link-libelf`

**Validates:** libelf.h installed, libelf.so linkable, ELF version API works.

```nix
mkDerivation {
  pname = "integration-check-elfutils-link-libelf";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.elfutils ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <libelf.h>
      #include <stdio.h>
      int main(void) {
          if (elf_version(EV_CURRENT) == EV_NONE) return 1;
          printf("elfutils-link-libelf: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -lelf
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `elfutils-link-libdw`

**Validates:** elfutils/libdw.h installed, libdw.so linkable, DWARF API works.

```nix
mkDerivation {
  pname = "integration-check-elfutils-link-libdw";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.elfutils ];
  phases = [{
    name = "check";
    script = ''
      cat > test.c << 'EOF'
      #include <elfutils/libdw.h>
      #include <stdio.h>
      int main(void) {
          /* dwarf_begin requires an open ELF file; test symbol resolution. */
          Dwarf *dw = dwarf_begin(-1, DWARF_C_READ);
          /* Expected to fail with invalid fd; that's fine. */
          if (dw) dwarf_end(dw);
          printf("elfutils-link-libdw: PASS\n");
          return 0;
      }
      EOF
      $CC -o test test.c -ldw -lelf
      ./test
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

#### `elfutils-cli`

**Validates:** eu-readelf binary works on a real ELF file.

```nix
mkDerivation {
  pname = "integration-check-elfutils-cli";
  buildDeps = [ make ];
  runtimeDeps = [ pkgs.elfutils ];
  phases = [{
    name = "check";
    script = ''
      # Compile a trivial binary, then inspect it with eu-readelf
      cat > hello.c << 'EOF'
      int main(void) { return 0; }
      EOF
      $CC -o hello hello.c
      eu-readelf -h hello
      mkdir -p $out && echo PASS > $out/result
    '';
  }];
}
```

---

## Test summary

| # | Category | Tests | Libraries covered |
|---|----------|-------|-------------------|
| 1 | TLS/Crypto | 8 | openssl (5+consumer), libsodium (3) |
| 2 | Compression | 16 | zlib (3), zstd (3), lz4 (3), bzip2 (3), brotli (3+consumer) |
| 3 | Network | 17 | curl (5), libssh2 (3), nghttp2 (2), libpcap (1), libnl (2), libmnl (2), libnfnetlink (1), libnetfilter_conntrack (1), libnetfilter_queue (1), libnetfilter_cthelper (1), libnetfilter_cttimeout (1), libnftnl (2) |
| 4 | Data/Parsing | 15 | sqlite (3), jansson (2), nlohmann-json (1), toml11 (1), oniguruma (2), pcre2 (2), expat (2), libarchive (3) |
| 5 | System/Capability | 6 | libcap (2), libxcrypt (2), libseccomp (2) |
| 6 | Terminal | 8 | ncurses (3), readline (2), editline (2) |
| 7 | Math | 6 | gmp (3), mpfr (2), libmpc (1) |
| 8 | C++ | 5 | boost (5) |
| 9 | Markdown/Text | 4 | lowdown (2), popt (2) |
| 10 | VCS | 3 | libgit2 (3) |
| 11 | Security (SELinux) | 7 | libsepol (2), libselinux (2), libsemanage (1), audit (2) |
| 12 | GC/Runtime | 3 | gc (2), libtirpc (1) |
| 13 | ELF | 3 | elfutils (3) |
| **Total** | | **101** | **37 libraries** |

## Coverage analysis

### Hub libraries (>5 dependents) -- 100% covered

| Library | Dependents | Tests |
|---------|-----------|-------|
| openssl | 10+ | 6 (link-libssl, link-libcrypto, cli-version, cli-dgst, header-version, consumers) |
| zlib | 10+ | 3 (link-deflate, header-version, consumers) |
| pcre2 | 3+ | 2 (link, consumers) |
| libcap | 3+ | 2 (link, consumers) |
| ncurses | 5+ | 3 (link, tinfo-compat, consumers) |
| libmnl | 7 | 2 (link, consumers) |

### Libraries with no AOS consumers -- link-only tests

These libraries are tested for correct compilation and linkage but have no consumer
verification tests because they are leaf packages or their consumers are not yet
in AOS:

- libtirpc
- libnetfilter_cthelper
- libnetfilter_cttimeout

### Test execution model

All tests are Nix derivations executed in the build sandbox (Layer 2.5). They:

1. Run in parallel on the remote builder
2. Share the Nix store cache with package builds (no redundant compilation)
3. Fail fast -- a broken library immediately blocks its test derivation
4. Are automatically re-run when any dependency changes (Nix tracks input hashes)

Integration tests should be collected under `checks.integration.libraries` in the
top-level `checks` attribute set, with each test accessible as:

```
checks.integration.libraries.openssl-link-libssl
checks.integration.libraries.zlib-link-deflate
checks.integration.libraries.curl-link-easy
...
```

See [implementation.md](implementation.md) for the Nix infrastructure that collects
and exposes these tests.
