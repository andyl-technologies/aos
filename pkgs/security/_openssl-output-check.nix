##! Verifies archive-only OpenSSL output selection without a VM or host tools.
{
  pkgs,
  openssl,
}: let
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  sharedExtension =
    if isDarwin
    then "dylib"
    else "so";
  runProbe = path:
    if pkgs.stdenv.isCross
    then ""
    else ''"${path}"'';
in
  pkgs.mkDerivation {
    pname = "openssl-output-split-check";
    version = openssl.version;
    src = ./openssl-output-check;

    buildDeps = [pkgs.cmake pkgs.gnumake pkgs.jq pkgs.pkg-config];
    runtimeDeps = [openssl pkgs.zlib];
    outputChecks = {};
    exportReferencesGraph.runtime = [openssl];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          test -s ${openssl}/lib/libcrypto.${sharedExtension}
          test -s ${openssl}/lib/libssl.${sharedExtension}
          test -s ${openssl}/include/openssl/ssl.h
          test -s ${openssl}/lib/pkgconfig/openssl.pc
          test ! -e ${openssl}/lib/cmake
          test ! -L ${openssl}/lib/cmake
          if find ${openssl} -name '*.a' -print -quit | grep -q .; then
            echo "OpenSSL runtime output still contains an archive" >&2
            exit 1
          fi
          test -s ${openssl.static}/lib/libcrypto.a
          test -s ${openssl.static}/lib/libssl.a
          jq -e --arg static ${openssl.static} \
            'all(.runtime[].path; . != $static)' "$NIX_ATTRS_JSON_FILE"

          # Existing headers, pkg-config and direct shared linking remain
          # usable without adding the static output to a consumer's closure.
          pkg-config --modversion openssl | grep -Fx ${openssl.version}
          "$CC" -std=c11 -Wall -Wextra -Werror "$src/probe.c" \
            -o dynamic-probe $(pkg-config --cflags --libs openssl)
          ${runProbe "./dynamic-probe"}

          # Absolute archives prevent an implicit shared-library fallback.
          # libc stays dynamic; this tests OpenSSL's static feature alone.
          "$CC" -std=c11 -Wall -Wextra -Werror "$src/probe.c" \
            -o static-probe ${openssl.static}/lib/libssl.a \
            ${openssl.static}/lib/libcrypto.a -lz -pthread ${
            if isDarwin
            then ""
            else "-ldl"
          }
          ${runProbe "./static-probe"}

          for mode in OFF ON; do
            if [ "$mode" = ON ]; then
              crypto=${openssl.static}/lib/libcrypto.a
              ssl=${openssl.static}/lib/libssl.a
            else
              crypto=${openssl}/lib/libcrypto.${sharedExtension}
              ssl=${openssl}/lib/libssl.${sharedExtension}
            fi
            cmake -S "$src" -B "cmake-$mode" \
              $cmakeFlags \
              -DCMAKE_C_COMPILER="$CC" \
              -DOpenSSL_DIR=${openssl.static}/lib/cmake/OpenSSL \
              -DOPENSSL_USE_STATIC_LIBS="$mode" \
              -DEXPECTED_INCLUDE=${openssl}/include \
              -DEXPECTED_RUNTIME=${openssl}/bin \
              -DEXPECTED_MODULES=${openssl}/lib/ossl-modules \
              -DEXPECTED_CRYPTO="$crypto" -DEXPECTED_SSL="$ssl"
            cmake --build "cmake-$mode" --parallel "$NIX_BUILD_CORES"
            ${runProbe "./cmake-$mode/openssl-output-probe"}
          done

          ${
            if pkgs.stdenv.isCross
            then ""
            else ''
              ${openssl}/bin/openssl version | grep -F "OpenSSL ${openssl.version}"
              printf abc | ${openssl}/bin/openssl dgst -sha256 \
                | grep -F ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            ''
          }

          mkdir -p "$out"
          printf '%s\n' 'OpenSSL output separation and linking passed' > "$out/result"
        '';
      }
    ];
  }
