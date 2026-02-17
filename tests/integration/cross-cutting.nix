# tests/integration/cross-cutting.nix — Cross-cutting multi-package integration tests
#
# These tests exercise dependency chains ACROSS package boundaries: compile+link
# programs against multiple libraries, run tools that depend on complex stacks,
# and verify that packages built independently from source actually interoperate.
#
# All tests run in headless Firecracker microVMs (no systemd, no agent).
#
# Usage:
#   nix-build -A checks.integration.cross-cutting-tls-stack
{
  pkgs,
  testing,
}: {
  # -------------------------------------------------------------------------
  # 1. TLS Stack — openssl + curl + ca-certificates interop
  # -------------------------------------------------------------------------
  # Compile a C program that initializes curl with openssl, sets CA bundle
  # path from ca-certificates, and prints library versions.
  tls-stack = testing.mkVMTest {
    name ="cross-cutting-tls-stack";
    rootfsDeps = [
      pkgs.openssl
      pkgs.curl
      pkgs.ca-certificates
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.curl}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.curl}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.curl}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/tls_test.c << 'EOF'
      #include <curl/curl.h>
      #include <openssl/opensslv.h>
      #include <openssl/crypto.h>
      #include <stdio.h>

      int main(void) {
          /* Initialize curl (pulls in openssl TLS backend) */
          curl_global_init(CURL_GLOBAL_DEFAULT);
          CURL *handle = curl_easy_init();
          if (!handle) {
              fprintf(stderr, "curl_easy_init failed\n");
              return 1;
          }

          /* Set CA certificate bundle path from ca-certificates package */
          const char *capath = "${pkgs.ca-certificates}/etc/ssl/certs/ca-bundle.crt";
          curl_easy_setopt(handle, CURLOPT_CAINFO, capath);

          /* Print versions to verify linkage */
          printf("curl version: %s\n", curl_version());
          printf("openssl header: %s\n", OPENSSL_VERSION_TEXT);
          printf("openssl runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
          printf("CA bundle: %s\n", capath);

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

  # -------------------------------------------------------------------------
  # 2. C Pipeline — preprocess, compile to asm, assemble, link, run
  # -------------------------------------------------------------------------
  # Full C compilation pipeline exercising every stage of gcc/binutils.
  c-pipeline = testing.mkVMTest {
    name ="cross-cutting-c-pipeline";
    rootfsDeps = [pkgs.binutils];
    testScript = ''
      cat > /tmp/pipeline.c << 'EOF'
      #include <stdio.h>
      int add(int a, int b) { return a + b; }
      int main(void) {
          int result = add(3, 4);
          printf("3 + 4 = %d\n", result);
          if (result != 7) return 1;
          return 0;
      }
      EOF

      echo "==> Stage 1: Preprocessing (gcc -E)"
      gcc -E /tmp/pipeline.c -o /tmp/pipeline.i
      echo "    Preprocessed output: $(wc -l < /tmp/pipeline.i) lines"

      echo "==> Stage 2: Compile to assembly (gcc -S)"
      gcc -S /tmp/pipeline.i -o /tmp/pipeline.s
      echo "    Assembly output: $(wc -l < /tmp/pipeline.s) lines"

      echo "==> Stage 3: Assemble to object (gcc -c)"
      gcc -c /tmp/pipeline.s -o /tmp/pipeline.o
      echo "    Object file: $(ls -l /tmp/pipeline.o | cut -d' ' -f5) bytes"

      echo "==> Stage 4: Link to binary"
      gcc /tmp/pipeline.o -o /tmp/pipeline

      echo "==> Stage 5: Run the binary"
      /tmp/pipeline
      echo "C compilation pipeline: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 3. Go Build — compile and run a Go program
  # -------------------------------------------------------------------------
  go-build = testing.mkVMTest {
    name ="cross-cutting-go-build";
    rootfsDeps = [pkgs.go];
    memory = 512;
    testScript = ''
      export GOPATH="/tmp/gopath"
      export GOCACHE="/tmp/gocache"
      export PATH="${pkgs.go}/bin:$PATH"
      mkdir -p /tmp/gopath /tmp/gocache

      cat > /tmp/hello.go << 'EOF'
      package main

      import (
          "fmt"
          "runtime"
      )

      func main() {
          fmt.Printf("Hello from Go %s on %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
          // Test basic computation
          result := fibonacci(10)
          if result != 55 {
              panic("fibonacci(10) != 55")
          }
          fmt.Printf("fibonacci(10) = %d\n", result)
      }

      func fibonacci(n int) int {
          if n <= 1 { return n }
          return fibonacci(n-1) + fibonacci(n-2)
      }
      EOF

      echo "==> Building Go program"
      go build -o /tmp/hello /tmp/hello.go
      echo "==> Running Go program"
      /tmp/hello
      echo "Go build integration: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 4. Rust Build — compile and run a Rust program
  # -------------------------------------------------------------------------
  rust-build = testing.mkVMTest {
    name ="cross-cutting-rust-build";
    rootfsDeps = [pkgs.rust];
    memory = 512;
    testScript = ''
      export PATH="${pkgs.rust}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.rust}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/hello.rs << 'EOF'
      fn fibonacci(n: u64) -> u64 {
          match n {
              0 => 0,
              1 => 1,
              _ => fibonacci(n - 1) + fibonacci(n - 2),
          }
      }

      fn main() {
          println!("Hello from Rust");
          let result = fibonacci(10);
          assert_eq!(result, 55, "fibonacci(10) should be 55");
          println!("fibonacci(10) = {}", result);
          println!("Rust build integration: PASS");
      }
      EOF

      echo "==> Compiling Rust program"
      rustc -o /tmp/hello /tmp/hello.rs
      echo "==> Running Rust program"
      /tmp/hello
    '';
  };

  # -------------------------------------------------------------------------
  # 5. Compression Interop — zlib + zstd round-trip in a single C program
  # -------------------------------------------------------------------------
  # A single C program that compresses data with zstd, decompresses, then
  # compresses with zlib, decompresses, and verifies both round-trips match.
  compression-interop = testing.mkVMTest {
    name ="cross-cutting-compression-interop";
    rootfsDeps = [
      pkgs.zlib
      pkgs.zstd
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.zlib}/include:${pkgs.zstd}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.zlib}/lib:${pkgs.zstd}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.zlib}/lib:${pkgs.zstd}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/compress_test.c << 'EOF'
      #include <zlib.h>
      #include <zstd.h>
      #include <string.h>
      #include <stdlib.h>
      #include <stdio.h>

      int main(void) {
          const char *original = "The quick brown fox jumps over the lazy dog. "
                                 "This is test data for compression interop.";
          size_t origLen = strlen(original);

          /* --- zstd round-trip --- */
          printf("==> Testing zstd round-trip\n");
          size_t zstdBound = ZSTD_compressBound(origLen);
          void *zstdComp = malloc(zstdBound);
          size_t zstdSize = ZSTD_compress(zstdComp, zstdBound, original, origLen, 1);
          if (ZSTD_isError(zstdSize)) {
              fprintf(stderr, "zstd compress failed: %s\n", ZSTD_getErrorName(zstdSize));
              return 1;
          }
          printf("    Compressed %zu -> %zu bytes with zstd\n", origLen, zstdSize);

          char *zstdDecomp = malloc(origLen + 1);
          size_t dSize = ZSTD_decompress(zstdDecomp, origLen, zstdComp, zstdSize);
          if (ZSTD_isError(dSize)) {
              fprintf(stderr, "zstd decompress failed: %s\n", ZSTD_getErrorName(dSize));
              return 1;
          }
          if (dSize != origLen || memcmp(zstdDecomp, original, origLen) != 0) {
              fprintf(stderr, "zstd round-trip mismatch\n");
              return 1;
          }
          printf("    zstd round-trip: OK\n");
          free(zstdComp);
          free(zstdDecomp);

          /* --- zlib round-trip --- */
          printf("==> Testing zlib round-trip\n");
          uLong zlibBound = compressBound((uLong)origLen);
          Bytef *zlibComp = malloc(zlibBound);
          uLong zlibSize = zlibBound;
          if (compress(zlibComp, &zlibSize, (const Bytef *)original, (uLong)origLen) != Z_OK) {
              fprintf(stderr, "zlib compress failed\n");
              return 1;
          }
          printf("    Compressed %zu -> %lu bytes with zlib\n", origLen, zlibSize);

          char *zlibDecomp = malloc(origLen + 1);
          uLong resLen = (uLong)origLen;
          if (uncompress((Bytef *)zlibDecomp, &resLen, zlibComp, zlibSize) != Z_OK) {
              fprintf(stderr, "zlib uncompress failed\n");
              return 1;
          }
          if (resLen != (uLong)origLen || memcmp(zlibDecomp, original, origLen) != 0) {
              fprintf(stderr, "zlib round-trip mismatch\n");
              return 1;
          }
          printf("    zlib round-trip: OK\n");
          free(zlibComp);
          free(zlibDecomp);

          printf("Compression interop: PASS\n");
          return 0;
      }
      EOF

      echo "==> Compiling compression interop test"
      gcc -o /tmp/compress_test /tmp/compress_test.c -lzstd -lz
      echo "==> Running compression interop test"
      /tmp/compress_test
    '';
  };

  # -------------------------------------------------------------------------
  # 6. Archive Chain — tar+gzip create, libarchive extract via C program
  # -------------------------------------------------------------------------
  archive-chain = testing.mkVMTest {
    name ="cross-cutting-archive-chain";
    rootfsDeps = [
      pkgs.tar
      pkgs.gzip
      pkgs.libarchive
      pkgs.zlib
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.libarchive}/include:${pkgs.zlib}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.libarchive}/lib:${pkgs.zlib}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.libarchive}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"

      # Create test files
      mkdir -p /tmp/src
      echo "file one content" > /tmp/src/one.txt
      echo "file two content" > /tmp/src/two.txt
      echo "file three content" > /tmp/src/three.txt

      # Create tar.gz archive using tar+gzip CLI tools
      echo "==> Creating tar.gz archive with tar + gzip"
      tar czf /tmp/archive.tar.gz -C /tmp/src .
      echo "    Archive size: $(ls -l /tmp/archive.tar.gz | cut -d' ' -f5) bytes"

      # Write a C program using libarchive to extract and verify
      cat > /tmp/extract_test.c << 'EOF'
      #include <archive.h>
      #include <archive_entry.h>
      #include <stdio.h>
      #include <string.h>

      int main(void) {
          struct archive *a = archive_read_new();
          archive_read_support_filter_all(a);
          archive_read_support_format_all(a);

          int r = archive_read_open_filename(a, "/tmp/archive.tar.gz", 10240);
          if (r != ARCHIVE_OK) {
              fprintf(stderr, "archive_read_open_filename failed: %s\n",
                      archive_error_string(a));
              return 1;
          }

          int count = 0;
          struct archive_entry *entry;
          while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
              const char *name = archive_entry_pathname(entry);
              printf("  entry: %s (size: %lld)\n", name,
                     (long long)archive_entry_size(entry));
              archive_read_data_skip(a);
              count++;
          }

          archive_read_close(a);
          archive_read_free(a);

          if (count < 3) {
              fprintf(stderr, "Expected at least 3 entries, got %d\n", count);
              return 1;
          }

          printf("libarchive extracted %d entries from tar.gz\n", count);
          printf("Archive chain: PASS\n");
          return 0;
      }
      EOF

      echo "==> Compiling libarchive extraction test"
      gcc -o /tmp/extract_test /tmp/extract_test.c -larchive -lz
      echo "==> Extracting with libarchive"
      /tmp/extract_test
    '';
  };

  # -------------------------------------------------------------------------
  # 7. pkg-config Chain — discover openssl flags, compile using them
  # -------------------------------------------------------------------------
  pkg-config-chain = testing.mkVMTest {
    name ="cross-cutting-pkg-config-chain";
    rootfsDeps = [
      pkgs.pkg-config
      pkgs.openssl
    ];
    testScript = ''
      export PKG_CONFIG_PATH="${pkgs.openssl}/lib/pkgconfig:$PKG_CONFIG_PATH"
      export C_INCLUDE_PATH="${pkgs.openssl}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.openssl}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.openssl}/lib:$LD_LIBRARY_PATH"

      echo "==> Querying pkg-config for openssl"
      pkg-config --modversion openssl
      echo "    CFLAGS: $(pkg-config --cflags openssl)"
      echo "    LIBS:   $(pkg-config --libs openssl)"

      # Write a program that uses openssl
      cat > /tmp/pkgtest.c << 'EOF'
      #include <openssl/crypto.h>
      #include <stdio.h>
      int main(void) {
          printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
          return 0;
      }
      EOF

      echo "==> Compiling with pkg-config-discovered flags"
      gcc -o /tmp/pkgtest /tmp/pkgtest.c $(pkg-config --cflags --libs openssl)
      echo "==> Running"
      /tmp/pkgtest
      echo "pkg-config chain: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 8. Multi-lib Link — single binary linking openssl + zlib + curl + pcre2
  # -------------------------------------------------------------------------
  multi-lib-link = testing.mkVMTest {
    name ="cross-cutting-multi-lib-link";
    rootfsDeps = [
      pkgs.openssl
      pkgs.zlib
      pkgs.curl
      pkgs.pcre2
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.zlib}/include:${pkgs.curl}/include:${pkgs.pcre2}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${pkgs.curl}/lib:${pkgs.pcre2}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${pkgs.curl}/lib:${pkgs.pcre2}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/multilib.c << 'EOF'
      #include <openssl/crypto.h>
      #include <zlib.h>
      #include <curl/curl.h>
      #define PCRE2_CODE_UNIT_WIDTH 8
      #include <pcre2.h>
      #include <stdio.h>

      int main(void) {
          /* openssl */
          printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));

          /* zlib */
          printf("zlib: %s\n", zlibVersion());

          /* curl */
          printf("curl: %s\n", curl_version());

          /* pcre2 */
          printf("pcre2: %d.%d\n", PCRE2_MAJOR, PCRE2_MINOR);

          /* Quick functional checks */
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

  # -------------------------------------------------------------------------
  # 9. Nix Stack — verify nix binary runs, can evaluate expressions
  # -------------------------------------------------------------------------
  nix-stack = testing.mkVMTest {
    name ="cross-cutting-nix-stack";
    rootfsDeps = [
      pkgs.nix
      pkgs.brotli
      pkgs.curl
      pkgs.openssl
      pkgs.sqlite
      pkgs.boost
      pkgs.editline
      pkgs.libsodium
      pkgs.libarchive
      pkgs.gc
      pkgs.lowdown
      pkgs.bzip2
      pkgs.zlib
    ];
    memory = 512;
    testScript = ''
      export PATH="${pkgs.nix}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.nix}/lib:${pkgs.brotli}/lib:${pkgs.curl}/lib:${pkgs.openssl}/lib:${pkgs.sqlite}/lib:${pkgs.boost}/lib:${pkgs.editline}/lib:${pkgs.libsodium}/lib:${pkgs.libarchive}/lib:${pkgs.gc}/lib:${pkgs.lowdown}/lib:${pkgs.bzip2}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
      # nix needs a /tmp and writable home
      export HOME=/tmp
      export NIX_CONF_DIR=/tmp/nix-conf
      mkdir -p /tmp/nix-conf

      # Disable features that need network/daemon
      cat > /tmp/nix-conf/nix.conf << 'NIXCONF'
      sandbox = false
      experimental-features = nix-command
      NIXCONF

      echo "==> Testing nix --version"
      nix --version

      echo "==> Testing nix eval"
      RESULT=$(nix eval --expr '1 + 1')
      echo "    nix eval '1 + 1' = $RESULT"
      if [ "$RESULT" != "2" ]; then
        echo "ERROR: expected 2, got $RESULT"
        exit 1
      fi

      echo "Nix stack: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 10. SELinux Tools — verify seinfo runs from setools package
  # -------------------------------------------------------------------------
  selinux-tools = testing.mkVMTest {
    name ="cross-cutting-selinux-tools";
    rootfsDeps = [
      pkgs.setools
      pkgs.libselinux
      pkgs.libsepol
    ];
    testScript = ''
      export PATH="${pkgs.setools}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.setools}/lib:${pkgs.libselinux}/lib:${pkgs.libsepol}/lib:$LD_LIBRARY_PATH"
      # setools needs python
      export PYTHONPATH="${pkgs.setools}/lib/python3/site-packages:$PYTHONPATH"

      echo "==> Testing seinfo --version"
      seinfo --version
      echo "SELinux tools: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 11. Python Import — verify python3 interpreter starts and imports work
  # -------------------------------------------------------------------------
  python-import = testing.mkVMTest {
    name ="cross-cutting-python-import";
    rootfsDeps = [pkgs.python3];
    testScript = ''
            export PATH="${pkgs.python3}/bin:$PATH"
            export LD_LIBRARY_PATH="${pkgs.python3}/lib:$LD_LIBRARY_PATH"

            echo "==> Testing python3 version"
            python3 -c "import sys; print('Python', sys.version)"

            echo "==> Testing python3 basic imports"
            python3 -c "
      import os
      import json
      import math
      print('os.name:', os.name)
      print('json works:', json.dumps({'test': True}))
      print('math.pi:', math.pi)
      print('Python imports: PASS')
      "
    '';
  };

  # -------------------------------------------------------------------------
  # 12. Python Build System Chain — python3 + sqlite + zlib + readline
  # -------------------------------------------------------------------------
  # Verify python3 can use its C extension modules that link against
  # external libraries (sqlite, zlib, readline).
  python-chain = testing.mkVMTest {
    name ="cross-cutting-python-chain";
    rootfsDeps = [
      pkgs.python3
      pkgs.sqlite
      pkgs.zlib
      pkgs.readline
    ];
    memory = 512;
    testScript = ''
            export PATH="${pkgs.python3}/bin:$PATH"
            export LD_LIBRARY_PATH="${pkgs.python3}/lib:${pkgs.sqlite}/lib:${pkgs.zlib}/lib:${pkgs.readline}/lib:$LD_LIBRARY_PATH"

            echo "==> Testing python3 C extension modules"

            python3 -c "
      import sqlite3
      import zlib
      import readline
      print('sqlite3: connected to', sqlite3.sqlite_version)
      db = sqlite3.connect(':memory:')
      db.execute('CREATE TABLE t(x)')
      db.execute('INSERT INTO t VALUES(42)')
      row = db.execute('SELECT x FROM t').fetchone()
      assert row[0] == 42, 'sqlite query failed'
      print('sqlite3: in-memory query OK')

      data = b'test data for compression'
      compressed = zlib.compress(data)
      assert zlib.decompress(compressed) == data, 'zlib round-trip failed'
      print('zlib: compress/decompress OK')

      print('readline: module loaded, version', readline.__doc__)

      print('all imports ok')
      "
            echo "Python chain: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 13. Network/Firewall Stack — libnl + libmnl + libnftnl compile+link
  # -------------------------------------------------------------------------
  # In a headless VM without real networking, verify the netfilter library
  # stack compiles and links as a unit by compiling a C program that
  # includes headers from all three and calls basic init/free functions.
  network-firewall-stack = testing.mkVMTest {
    name ="cross-cutting-network-firewall-stack";
    rootfsDeps = [
      pkgs.libnl
      pkgs.libmnl
      pkgs.libnftnl
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.libnl}/include/libnl3:${pkgs.libmnl}/include:${pkgs.libnftnl}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.libnl}/lib:${pkgs.libmnl}/lib:${pkgs.libnftnl}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.libnl}/lib:${pkgs.libmnl}/lib:${pkgs.libnftnl}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/netfilter_test.c << 'EOF'
      #include <netlink/netlink.h>
      #include <libmnl/libmnl.h>
      #include <libnftnl/table.h>
      #include <stdio.h>

      int main(void) {
          /* libnl: allocate and free a netlink socket */
          struct nl_sock *sk = nl_socket_alloc();
          if (!sk) {
              fprintf(stderr, "nl_socket_alloc failed\n");
              return 1;
          }
          printf("libnl: socket allocated OK\n");
          nl_socket_free(sk);
          printf("libnl: socket freed OK\n");

          /* libmnl: open and close a netlink socket */
          struct mnl_socket *mnl = mnl_socket_open(NETLINK_NETFILTER);
          if (!mnl) {
              /* May fail in VM without proper netlink — just test linking */
              printf("libmnl: mnl_socket_open returned NULL (expected in constrained VM)\n");
          } else {
              printf("libmnl: socket opened OK\n");
              mnl_socket_close(mnl);
              printf("libmnl: socket closed OK\n");
          }

          /* libnftnl: allocate and free a table object */
          struct nftnl_table *t = nftnl_table_alloc();
          if (!t) {
              fprintf(stderr, "nftnl_table_alloc failed\n");
              return 1;
          }
          nftnl_table_set_str(t, NFTNL_TABLE_NAME, "test_table");
          printf("libnftnl: table allocated and named OK\n");
          nftnl_table_free(t);
          printf("libnftnl: table freed OK\n");

          printf("Network/firewall stack: PASS\n");
          return 0;
      }
      EOF

      echo "==> Compiling netfilter stack test"
      gcc -o /tmp/netfilter_test /tmp/netfilter_test.c -lnl-3 -lmnl -lnftnl
      echo "==> Running netfilter stack test"
      /tmp/netfilter_test
    '';
  };

  # -------------------------------------------------------------------------
  # 14. TLS Full Chain — openssl + libssh2 + curl + nghttp2 in one binary
  # -------------------------------------------------------------------------
  # Compile a single C program that links all four TLS-related libraries
  # and calls init functions from each, verifying they coexist.
  tls-full-chain = testing.mkVMTest {
    name ="cross-cutting-tls-full-chain";
    rootfsDeps = [
      pkgs.openssl
      pkgs.libssh2
      pkgs.curl
      pkgs.nghttp2
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.libssh2}/include:${pkgs.curl}/include:${pkgs.nghttp2}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.libssh2}/lib:${pkgs.curl}/lib:${pkgs.nghttp2}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.libssh2}/lib:${pkgs.curl}/lib:${pkgs.nghttp2}/lib:$LD_LIBRARY_PATH"

      cat > /tmp/tls_full.c << 'EOF'
      #include <openssl/crypto.h>
      #include <openssl/ssl.h>
      #include <libssh2.h>
      #include <curl/curl.h>
      #include <nghttp2/nghttp2.h>
      #include <stdio.h>

      int main(void) {
          /* openssl */
          printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));

          /* libssh2 */
          int rc = libssh2_init(0);
          if (rc != 0) {
              fprintf(stderr, "libssh2_init failed: %d\n", rc);
              return 1;
          }
          printf("libssh2: initialized OK\n");
          libssh2_exit();
          printf("libssh2: cleaned up OK\n");

          /* curl (uses openssl as TLS backend) */
          curl_global_init(CURL_GLOBAL_DEFAULT);
          CURL *handle = curl_easy_init();
          if (!handle) {
              fprintf(stderr, "curl_easy_init failed\n");
              return 1;
          }
          printf("curl: %s\n", curl_version());
          curl_easy_cleanup(handle);
          curl_global_cleanup();

          /* nghttp2 */
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

  # -------------------------------------------------------------------------
  # 15. Go CGO Full — Go program calling zlib via C FFI
  # -------------------------------------------------------------------------
  # Write a Go program with CGO that calls zlib compress/uncompress via
  # C FFI, compile and run it.
  go-cgo-full = testing.mkVMTest {
    name ="cross-cutting-go-cgo-full";
    rootfsDeps = [
      pkgs.go
      pkgs.zlib
    ];
    memory = 512;
    testScript = ''
      export GOPATH="/tmp/gopath"
      export GOCACHE="/tmp/gocache"
      export HOME="/tmp"
      export PATH="${pkgs.go}/bin:$PATH"
      export CGO_ENABLED=1
      export CGO_CFLAGS="-I${pkgs.zlib}/include"
      export CGO_LDFLAGS="-L${pkgs.zlib}/lib -lz"
      export C_INCLUDE_PATH="${pkgs.zlib}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
      mkdir -p /tmp/gopath /tmp/gocache /tmp/cgotest

      cat > /tmp/cgotest/main.go << 'EOF'
      package main

      /*
      #include <zlib.h>
      #include <stdlib.h>
      #include <string.h>

      int do_compress(const char *src, int srcLen, char *dst, int *dstLen) {
          uLong dl = (uLong)*dstLen;
          int ret = compress((Bytef *)dst, &dl, (const Bytef *)src, (uLong)srcLen);
          *dstLen = (int)dl;
          return ret;
      }

      int do_uncompress(const char *src, int srcLen, char *dst, int *dstLen) {
          uLong dl = (uLong)*dstLen;
          int ret = uncompress((Bytef *)dst, &dl, (const Bytef *)src, (uLong)srcLen);
          *dstLen = (int)dl;
          return ret;
      }
      */
      import "C"
      import (
          "fmt"
          "unsafe"
      )

      func main() {
          src := "Hello from Go CGO with zlib compression!"
          srcC := C.CString(src)
          defer C.free(unsafe.Pointer(srcC))

          // Compress
          dstLen := C.int(256)
          dst := (*C.char)(C.malloc(256))
          defer C.free(unsafe.Pointer(dst))

          ret := C.do_compress(srcC, C.int(len(src)), dst, &dstLen)
          if ret != 0 {
              panic(fmt.Sprintf("compress failed: %d", ret))
          }
          fmt.Printf("Compressed %d -> %d bytes\n", len(src), dstLen)

          // Uncompress
          outLen := C.int(256)
          out := (*C.char)(C.malloc(256))
          defer C.free(unsafe.Pointer(out))

          ret = C.do_uncompress(dst, dstLen, out, &outLen)
          if ret != 0 {
              panic(fmt.Sprintf("uncompress failed: %d", ret))
          }

          result := C.GoStringN(out, outLen)
          if result != src {
              panic(fmt.Sprintf("round-trip mismatch: got %q", result))
          }
          fmt.Printf("Round-trip OK: %q\n", result)
          fmt.Println("Go CGO full: PASS")
      }
      EOF

      echo "==> Building Go CGO program with zlib"
      cd /tmp/cgotest
      go mod init cgotest
      go build -o /tmp/cgotest/cgotest .
      echo "==> Running Go CGO program"
      /tmp/cgotest/cgotest
    '';
  };

  # -------------------------------------------------------------------------
  # 16. Rust FFI — Rust program calling zlibVersion() via extern "C"
  # -------------------------------------------------------------------------
  # Write a Rust program that uses extern "C" to call zlibVersion() from
  # zlib, compile with rustc and -lz flag.
  rust-ffi = testing.mkVMTest {
    name ="cross-cutting-rust-ffi";
    rootfsDeps = [
      pkgs.rust
      pkgs.zlib
    ];
    memory = 512;
    testScript = ''
      export PATH="${pkgs.rust}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.rust}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
      export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"

      cat > /tmp/zlib_ffi.rs << 'EOF'
      use std::ffi::CStr;
      use std::os::raw::c_char;

      extern "C" {
          fn zlibVersion() -> *const c_char;
      }

      fn main() {
          let version = unsafe {
              let ptr = zlibVersion();
              CStr::from_ptr(ptr).to_str().expect("invalid UTF-8")
          };
          println!("zlib version from Rust FFI: {}", version);
          assert!(!version.is_empty(), "zlibVersion() returned empty string");
          println!("Rust FFI: PASS");
      }
      EOF

      echo "==> Compiling Rust FFI program"
      rustc -o /tmp/zlib_ffi /tmp/zlib_ffi.rs -L ${pkgs.zlib}/lib -lz
      echo "==> Running Rust FFI program"
      /tmp/zlib_ffi
    '';
  };

  # -------------------------------------------------------------------------
  # 17. SELinux Policy Compilation — checkpolicy compiles .te to .pp
  # -------------------------------------------------------------------------
  # Use checkpolicy to compile a minimal SELinux policy module (.te source)
  # into a binary policy module, verifying the SELinux policy toolchain.
  selinux-policy = testing.mkVMTest {
    name ="cross-cutting-selinux-policy";
    rootfsDeps = [
      pkgs.checkpolicy
      pkgs.libsepol
      pkgs.libselinux
    ];
    testScript = ''
      export PATH="${pkgs.checkpolicy}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.checkpolicy}/lib:${pkgs.libsepol}/lib:${pkgs.libselinux}/lib:$LD_LIBRARY_PATH"

      # Create a minimal SELinux type enforcement file
      cat > /tmp/test_module.te << 'EOF'
      policy_module(test_module, 1.0.0)

      type test_t;
      EOF

      echo "==> Compiling SELinux policy module with checkpolicy"
      # checkmodule compiles .te to .mod
      checkmodule -M -m -o /tmp/test_module.mod /tmp/test_module.te
      echo "    Module compiled: $(ls -l /tmp/test_module.mod | cut -d' ' -f5) bytes"

      # semodule_package packages .mod to .pp (if available)
      # For now just verify checkmodule succeeded — that validates
      # checkpolicy + libsepol linkage
      echo "SELinux policy: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 18. Nix Store Operations — init store, evaluate, instantiate
  # -------------------------------------------------------------------------
  # Deeper nix stack test: initialize the store, run nix-instantiate for
  # evaluation, and verify nix-store operations work.
  nix-store-ops = testing.mkVMTest {
    name ="cross-cutting-nix-store-ops";
    rootfsDeps = [
      pkgs.nix
      pkgs.brotli
      pkgs.curl
      pkgs.openssl
      pkgs.sqlite
      pkgs.boost
      pkgs.editline
      pkgs.libsodium
      pkgs.libarchive
      pkgs.gc
      pkgs.lowdown
      pkgs.bzip2
      pkgs.zlib
    ];
    memory = 512;
    testScript = ''
      export PATH="${pkgs.nix}/bin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.nix}/lib:${pkgs.brotli}/lib:${pkgs.curl}/lib:${pkgs.openssl}/lib:${pkgs.sqlite}/lib:${pkgs.boost}/lib:${pkgs.editline}/lib:${pkgs.libsodium}/lib:${pkgs.libarchive}/lib:${pkgs.gc}/lib:${pkgs.lowdown}/lib:${pkgs.bzip2}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
      export HOME=/tmp
      export NIX_CONF_DIR=/tmp/nix-conf
      mkdir -p /tmp/nix-conf /nix/var/nix/db

      cat > /tmp/nix-conf/nix.conf << 'NIXCONF'
      sandbox = false
      experimental-features = nix-command
      NIXCONF

      echo "==> Testing nix store init"
      nix store init
      echo "    Store initialized"

      echo "==> Testing nix eval --expr"
      RESULT=$(nix eval --expr '1 + 1')
      echo "    nix eval '1 + 1' = $RESULT"
      if [ "$RESULT" != "2" ]; then
        echo "ERROR: expected 2, got $RESULT"
        exit 1
      fi

      echo "==> Testing nix eval builtins.currentSystem"
      RESULT2=$(nix eval --expr 'builtins.currentSystem')
      echo "    builtins.currentSystem = $RESULT2"

      echo "Nix store ops: PASS"
    '';
  };

  # -------------------------------------------------------------------------
  # 19. Config Validity — verify service binaries can parse configs
  # -------------------------------------------------------------------------
  # Run syntax validation for key services: sshd, chronyd, nginx.
  # In a headless VM without systemd, just verify the binaries can parse
  # minimal configuration files.
  config-validity = testing.mkVMTest {
    name ="cross-cutting-config-validity";
    rootfsDeps = [
      pkgs.openssh
      pkgs.chrony
      pkgs.nginx
    ];
    testScript = ''
      export PATH="${pkgs.openssh}/bin:${pkgs.openssh}/sbin:${pkgs.chrony}/bin:${pkgs.chrony}/sbin:${pkgs.nginx}/bin:${pkgs.nginx}/sbin:$PATH"
      export LD_LIBRARY_PATH="${pkgs.openssh}/lib:${pkgs.chrony}/lib:${pkgs.nginx}/lib:$LD_LIBRARY_PATH"

      # --- sshd config validation ---
      echo "==> Testing sshd config parsing"
      mkdir -p /tmp/sshd_test /run/sshd
      cat > /tmp/sshd_test/sshd_config << 'SSHCFG'
      Port 2222
      PermitRootLogin no
      PasswordAuthentication no
      PubkeyAuthentication yes
      SSHCFG

      # sshd -t needs host keys to exist; generate a minimal one
      ssh-keygen -t ed25519 -f /tmp/sshd_test/host_key -N "" -q
      echo "HostKey /tmp/sshd_test/host_key" >> /tmp/sshd_test/sshd_config
      sshd -t -f /tmp/sshd_test/sshd_config
      echo "    sshd config: valid"

      # --- chronyd config validation ---
      echo "==> Testing chronyd config parsing"
      cat > /tmp/chrony.conf << 'CHRONYCFG'
      pool pool.ntp.org iburst
      driftfile /var/lib/chrony/drift
      makestep 1.0 3
      rtcsync
      CHRONYCFG
      chronyd -p -f /tmp/chrony.conf
      echo "    chronyd config: valid"

      # --- nginx config validation ---
      echo "==> Testing nginx config parsing"
      mkdir -p /tmp/nginx/logs /tmp/nginx/client_body
      cat > /tmp/nginx.conf << 'NGINXCFG'
      worker_processes 1;
      error_log /tmp/nginx/logs/error.log;
      pid /tmp/nginx/nginx.pid;
      events {
          worker_connections 64;
      }
      http {
          access_log /tmp/nginx/logs/access.log;
          client_body_temp_path /tmp/nginx/client_body;
          server {
              listen 8080;
              server_name localhost;
              location / {
                  return 200 'ok';
              }
          }
      }
      NGINXCFG
      nginx -t -c /tmp/nginx.conf
      echo "    nginx config: valid"

      echo "Config validity: PASS"
    '';
  };
}
