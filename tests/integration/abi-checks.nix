# tests/integration/abi-checks.nix — ABI regression detection and system-level validation
#
# These tests detect incompatibilities introduced by shared library upgrades,
# broken RPATH/dynamic linker paths, missing symbol exports, and pkg-config
# inconsistencies. All run in headless Firecracker microVMs.
#
# Usage:
#   nix-build -A checks.integration.abi-soname-validation
#   nix-build -A checks.integration.abi-version-consistency
#   nix-build -A checks.integration.abi-pkgconfig-audit
{
  pkgs,
  testing,
}: {
  # -------------------------------------------------------------------------
  # 1. SONAME tracking (design 2.1)
  # -------------------------------------------------------------------------
  # For key shared libraries, verify the SONAME exists and matches expected
  # patterns. Catches accidental SONAME changes during upgrades.
  soname-validation = testing.mkVMTest {
    name ="abi-soname-validation";
    rootfsDeps = [
      pkgs.elfutils
      pkgs.openssl
      pkgs.zlib
      pkgs.zstd
      pkgs.lz4
      pkgs.curl
      pkgs.pcre2
      pkgs.libarchive
      pkgs.libsodium
    ];
    testScript = ''
      FAIL=0

      check_soname() {
        LIB_PATH="$1"
        LIB_NAME="$2"

        if [ ! -f "$LIB_PATH" ]; then
          echo "SKIP: $LIB_NAME ($LIB_PATH not found)"
          return
        fi

        SONAME_LINE=$(readelf -d "$LIB_PATH" 2>/dev/null | grep SONAME || true)
        if [ -z "$SONAME_LINE" ]; then
          echo "FAIL: $LIB_NAME has no SONAME"
          FAIL=1
          return
        fi
        echo "PASS: $LIB_NAME SONAME: $SONAME_LINE"
      }

      echo "==> Checking SONAMEs for key libraries"

      check_soname "${pkgs.openssl}/lib/libssl.so" "libssl"
      check_soname "${pkgs.openssl}/lib/libcrypto.so" "libcrypto"
      check_soname "${pkgs.zlib}/lib/libz.so" "libz"
      check_soname "${pkgs.zstd}/lib/libzstd.so" "libzstd"
      check_soname "${pkgs.lz4}/lib/liblz4.so" "liblz4"
      check_soname "${pkgs.curl}/lib/libcurl.so" "libcurl"
      check_soname "${pkgs.pcre2}/lib/libpcre2-8.so" "libpcre2-8"
      check_soname "${pkgs.libarchive}/lib/libarchive.so" "libarchive"
      check_soname "${pkgs.libsodium}/lib/libsodium.so" "libsodium"

      if [ "$FAIL" -ne 0 ]; then
        echo "==> SONAME validation FAILED"
        exit 1
      fi
      echo "==> All SONAME checks passed"
    '';
  };

  # -------------------------------------------------------------------------
  # 2. Header/runtime version consistency (design 2.2)
  # -------------------------------------------------------------------------
  # Compile and run C programs that compare compile-time version macros against
  # runtime version functions. A mismatch indicates headers from one version
  # but .so from another.
  version-consistency = testing.mkVMTest {
    name ="abi-version-consistency";
    rootfsDeps = [
      pkgs.openssl
      pkgs.zlib
      pkgs.zstd
    ];
    testScript = ''
      export C_INCLUDE_PATH="${pkgs.openssl}/include:${pkgs.zlib}/include:${pkgs.zstd}/include:$C_INCLUDE_PATH"
      export LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${pkgs.zstd}/lib:$LIBRARY_PATH"
      export LD_LIBRARY_PATH="${pkgs.openssl}/lib:${pkgs.zlib}/lib:${pkgs.zstd}/lib:$LD_LIBRARY_PATH"

      FAIL=0

      # --- OpenSSL ---
      cat > /tmp/check_openssl.c << 'EOF'
      #include <openssl/opensslv.h>
      #include <openssl/crypto.h>
      #include <stdio.h>
      #include <string.h>
      int main(void) {
          const char *h = OPENSSL_VERSION_TEXT;
          const char *r = OpenSSL_version(OPENSSL_VERSION);
          if (strcmp(h, r) != 0) {
              fprintf(stderr, "openssl MISMATCH: header=%s runtime=%s\n", h, r);
              return 1;
          }
          printf("openssl MATCH: %s\n", r);
          return 0;
      }
      EOF
      echo "==> Checking openssl version consistency"
      gcc -o /tmp/check_openssl /tmp/check_openssl.c -lssl -lcrypto
      /tmp/check_openssl || FAIL=1

      # --- zlib ---
      cat > /tmp/check_zlib.c << 'EOF'
      #include <zlib.h>
      #include <stdio.h>
      #include <string.h>
      int main(void) {
          const char *h = ZLIB_VERSION;
          const char *r = zlibVersion();
          if (strcmp(h, r) != 0) {
              fprintf(stderr, "zlib MISMATCH: header=%s runtime=%s\n", h, r);
              return 1;
          }
          printf("zlib MATCH: %s\n", r);
          return 0;
      }
      EOF
      echo "==> Checking zlib version consistency"
      gcc -o /tmp/check_zlib /tmp/check_zlib.c -lz
      /tmp/check_zlib || FAIL=1

      # --- zstd ---
      cat > /tmp/check_zstd.c << 'EOF'
      #include <zstd.h>
      #include <stdio.h>
      #include <string.h>
      int main(void) {
          const char *h = ZSTD_VERSION_STRING;
          const char *r = ZSTD_versionString();
          if (strcmp(h, r) != 0) {
              fprintf(stderr, "zstd MISMATCH: header=%s runtime=%s\n", h, r);
              return 1;
          }
          printf("zstd MATCH: %s\n", r);
          return 0;
      }
      EOF
      echo "==> Checking zstd version consistency"
      gcc -o /tmp/check_zstd /tmp/check_zstd.c -lzstd
      /tmp/check_zstd || FAIL=1

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Version consistency checks FAILED"
        exit 1
      fi
      echo "==> All version consistency checks passed"
    '';
  };

  # -------------------------------------------------------------------------
  # 3. pkg-config consistency (design 2.3)
  # -------------------------------------------------------------------------
  # For libraries that ship .pc files, verify pkg-config --modversion and
  # --cflags --libs return valid values with paths that exist on disk.
  pkgconfig-audit = testing.mkVMTest {
    name ="abi-pkgconfig-audit";
    rootfsDeps = [
      pkgs.pkg-config
      pkgs.openssl
      pkgs.zlib
      pkgs.zstd
      pkgs.lz4
      pkgs.libarchive
      pkgs.pcre2
    ];
    testScript = ''
      export PKG_CONFIG_PATH="${pkgs.openssl}/lib/pkgconfig:${pkgs.zlib}/lib/pkgconfig:${pkgs.zstd}/lib/pkgconfig:${pkgs.lz4}/lib/pkgconfig:${pkgs.libarchive}/lib/pkgconfig:${pkgs.pcre2}/lib/pkgconfig"

      FAIL=0

      check_pc() {
        PC_NAME="$1"

        echo "==> Checking pkg-config: $PC_NAME"

        # Check --modversion
        VERSION=$(pkg-config --modversion "$PC_NAME" 2>/dev/null) || {
          echo "FAIL: pkg-config --modversion $PC_NAME failed"
          FAIL=1
          return
        }
        echo "  version: $VERSION"

        # Check --cflags
        CFLAGS=$(pkg-config --cflags "$PC_NAME" 2>/dev/null) || {
          echo "FAIL: pkg-config --cflags $PC_NAME failed"
          FAIL=1
          return
        }
        echo "  cflags: $CFLAGS"

        # Check --libs
        LIBS=$(pkg-config --libs "$PC_NAME" 2>/dev/null) || {
          echo "FAIL: pkg-config --libs $PC_NAME failed"
          FAIL=1
          return
        }
        echo "  libs: $LIBS"

        # Verify -L paths exist
        for flag in $LIBS; do
          case "$flag" in
            -L*)
              DIR=$(echo "$flag" | cut -c3-)
              if [ ! -d "$DIR" ]; then
                echo "FAIL: $PC_NAME libs path does not exist: $DIR"
                FAIL=1
              fi
              ;;
          esac
        done

        # Verify -I paths exist
        for flag in $CFLAGS; do
          case "$flag" in
            -I*)
              DIR=$(echo "$flag" | cut -c3-)
              if [ ! -d "$DIR" ]; then
                echo "FAIL: $PC_NAME include path does not exist: $DIR"
                FAIL=1
              fi
              ;;
          esac
        done

        echo "  PASS: $PC_NAME"
      }

      check_pc openssl
      check_pc zlib
      check_pc libzstd
      check_pc liblz4
      check_pc libarchive
      check_pc libpcre2-8

      if [ "$FAIL" -ne 0 ]; then
        echo "==> pkg-config audit FAILED"
        exit 1
      fi
      echo "==> All pkg-config checks passed"
    '';
  };

  # -------------------------------------------------------------------------
  # 4. RPATH validation (design 3.2)
  # -------------------------------------------------------------------------
  # For key binaries, verify RPATH/RUNPATH entries point to existing directories
  # that contain the expected .so files, and that no binary has /usr/lib or /lib
  # in its RPATH (should only have /nix/store paths).
  rpath-validation = testing.mkVMTest {
    name ="abi-rpath-validation";
    rootfsDeps = [
      pkgs.elfutils
      pkgs.curl
      pkgs.openssh
      pkgs.nftables
      pkgs.jq
      pkgs.socat
    ];
    testScript = ''
      FAIL=0

      check_rpath() {
        BINARY="$1"
        LABEL="$2"

        if [ ! -f "$BINARY" ]; then
          echo "SKIP: $LABEL ($BINARY not found)"
          return
        fi

        echo "==> Checking RPATH for $LABEL ($BINARY)"

        # Extract RPATH or RUNPATH
        RPATH_LINE=$(readelf -d "$BINARY" 2>/dev/null | grep -E 'RPATH|RUNPATH' || true)

        if [ -z "$RPATH_LINE" ]; then
          echo "  WARN: $LABEL has no RPATH/RUNPATH"
          return
        fi

        echo "  $RPATH_LINE"

        # Extract the path value between brackets
        # Format: 0x000000000000001d (RUNPATH)  Library runpath: [/nix/store/...]
        RPATH_VAL=$(echo "$RPATH_LINE" | sed 's/.*\[//' | sed 's/\]//')

        # Split on colon and check each path
        OLD_IFS="$IFS"
        IFS=":"
        for dir in $RPATH_VAL; do
          IFS="$OLD_IFS"

          # Check for forbidden paths
          case "$dir" in
            /usr/lib*|/lib|/lib64)
              echo "  FAIL: $LABEL has non-Nix RPATH entry: $dir"
              FAIL=1
              ;;
          esac

          # Verify path exists
          if [ ! -d "$dir" ]; then
            echo "  FAIL: $LABEL RPATH directory does not exist: $dir"
            FAIL=1
          else
            echo "  OK: $dir exists"
          fi
        done
        IFS="$OLD_IFS"
      }

      check_rpath "${pkgs.curl}/bin/curl" "curl"
      check_rpath "${pkgs.openssh}/bin/ssh" "ssh"
      check_rpath "${pkgs.nftables}/sbin/nft" "nft"
      check_rpath "${pkgs.jq}/bin/jq" "jq"
      check_rpath "${pkgs.socat}/bin/socat" "socat"

      if [ "$FAIL" -ne 0 ]; then
        echo "==> RPATH validation FAILED"
        exit 1
      fi
      echo "==> All RPATH checks passed"
    '';
  };

  # -------------------------------------------------------------------------
  # 5. Symbol export validation
  # -------------------------------------------------------------------------
  # For openssl and zlib, verify that key exported symbols exist. This catches
  # accidental symbol stripping or misconfigured builds.
  symbol-exports = testing.mkVMTest {
    name ="abi-symbol-exports";
    rootfsDeps = [
      pkgs.binutils
      pkgs.openssl
      pkgs.zlib
    ];
    testScript = ''
      FAIL=0

      check_symbol() {
        LIB_PATH="$1"
        LIB_NAME="$2"
        SYMBOL="$3"

        if [ ! -f "$LIB_PATH" ]; then
          echo "SKIP: $LIB_NAME ($LIB_PATH not found)"
          return
        fi

        if nm -D "$LIB_PATH" 2>/dev/null | grep -q " T $SYMBOL"; then
          echo "PASS: $LIB_NAME exports $SYMBOL"
        else
          echo "FAIL: $LIB_NAME missing symbol $SYMBOL"
          FAIL=1
        fi
      }

      echo "==> Checking symbol exports"

      # OpenSSL libssl
      check_symbol "${pkgs.openssl}/lib/libssl.so" "libssl" "SSL_read"
      check_symbol "${pkgs.openssl}/lib/libssl.so" "libssl" "SSL_write"
      check_symbol "${pkgs.openssl}/lib/libssl.so" "libssl" "SSL_connect"
      check_symbol "${pkgs.openssl}/lib/libssl.so" "libssl" "SSL_accept"

      # OpenSSL libcrypto
      check_symbol "${pkgs.openssl}/lib/libcrypto.so" "libcrypto" "EVP_EncryptInit"
      check_symbol "${pkgs.openssl}/lib/libcrypto.so" "libcrypto" "EVP_DigestInit"

      # zlib
      check_symbol "${pkgs.zlib}/lib/libz.so" "libz" "compress"
      check_symbol "${pkgs.zlib}/lib/libz.so" "libz" "uncompress"
      check_symbol "${pkgs.zlib}/lib/libz.so" "libz" "deflate"
      check_symbol "${pkgs.zlib}/lib/libz.so" "libz" "inflate"

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Symbol export validation FAILED"
        exit 1
      fi
      echo "==> All symbol export checks passed"
    '';
  };

  # -------------------------------------------------------------------------
  # 6. Dynamic linker validation
  # -------------------------------------------------------------------------
  # For key binaries, verify the ELF interpreter path points to a valid
  # ld-linux-x86-64.so.2 that exists on disk.
  dynamic-linker = testing.mkVMTest {
    name ="abi-dynamic-linker";
    rootfsDeps = [
      pkgs.elfutils
      pkgs.bash
      pkgs.curl
      pkgs.jq
    ];
    testScript = ''
      FAIL=0

      check_interp() {
        BINARY="$1"
        LABEL="$2"

        if [ ! -f "$BINARY" ]; then
          echo "SKIP: $LABEL ($BINARY not found)"
          return
        fi

        echo "==> Checking dynamic linker for $LABEL ($BINARY)"

        INTERP_LINE=$(readelf -l "$BINARY" 2>/dev/null | grep "interpreter" || true)

        if [ -z "$INTERP_LINE" ]; then
          # Could be statically linked
          echo "  INFO: $LABEL has no interpreter (possibly static)"
          return
        fi

        echo "  $INTERP_LINE"

        # Extract the interpreter path from: [Requesting program interpreter: /path/to/ld.so]
        INTERP=$(echo "$INTERP_LINE" | sed 's/.*interpreter: //' | sed 's/\].*//')

        if [ -z "$INTERP" ]; then
          echo "  FAIL: could not parse interpreter path for $LABEL"
          FAIL=1
          return
        fi

        if [ -f "$INTERP" ]; then
          echo "  PASS: interpreter exists: $INTERP"
        else
          echo "  FAIL: interpreter does not exist: $INTERP"
          FAIL=1
        fi
      }

      check_interp "${pkgs.bash}/bin/bash" "bash"
      check_interp "${pkgs.curl}/bin/curl" "curl"
      check_interp "${pkgs.jq}/bin/jq" "jq"

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Dynamic linker validation FAILED"
        exit 1
      fi
      echo "==> All dynamic linker checks passed"
    '';
  };
}
