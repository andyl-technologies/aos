##! Pinned BoringSSL source required by Netty TCNative 2.0.56.Final.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  stdenv,
}: let
  revision = "3a667d10e94186fd503966f5638e134fe9fb4080";
  installNameToolFlag =
    if stdenv.hostPlatform.isDarwin
    then "-DCMAKE_INSTALL_NAME_TOOL=${buildPackages.llvm}/bin/llvm-install-name-tool"
    else "";
in
  mkDerivation {
    pname = "bazel-netty-boringssl";
    version = "2021-11-22";

    src = fetchgit {
      url = "https://github.com/google/boringssl.git";
      rev = revision;
      name = "boringssl-${revision}-source-only";
      hash = "sha256-qBIMKiaOm7JMCS/g5OazWhXrIX89jhk74qW5E30rpo0=";
      deepClone = true;
      git = buildPackages.git-minimal;
      caCertificates = buildPackages.ca-certificates;
      coreutils = buildPackages.coreutils;
      sparsePatterns = [
        "/*"
        "!/fuzz/"
        "!/util/ar/testdata/"
        "!/util/fipstools/acvp/acvptool/test/"
        "!/crypto/fipsmodule/*.png"
        "!/crypto/fipsmodule/policydocs/"
        "!/crypto/pkcs8/test/*.p12"
      ];
    };

    buildDeps =
      [
        buildPackages.cmake
        buildPackages.ninja
        buildPackages.perl
        buildPackages.go
        buildPackages.python3
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.llvm]
        else []
      );
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          cp -R "$src"/. source/
          # Modern GCC reports new warnings in this pinned release.
          sed -i 's/set(C_CXX_FLAGS "-Werror /set(C_CXX_FLAGS "/' source/CMakeLists.txt

          python3 - <<'PY'
          from pathlib import Path

          files = [path for path in Path("source").rglob("*") if path.is_file()]
          if len(files) != 1413:
              raise SystemExit(f"Unexpected BoringSSL source inventory: {len(files)} files")
          for path in files:
              path.read_text(encoding="utf-8")
          PY
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S source -B build -G Ninja $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DBUILD_SHARED_LIBS=OFF ${installNameToolFlag}
        '';
      }
      {
        name = "build";
        script = ''
          # The error-table generator imports only the Go standard library.
          # Module mode would try to resolve unrelated test dependencies.
          export GO111MODULE=off
          export GOCACHE="$PWD/go-cache"
          mkdir -p "$GOCACHE"
          ninja -C build -j"$NIX_BUILD_CORES" crypto ssl
        '';
      }
      {
        name = "check";
        script = ''
          test -s build/crypto/libcrypto.a
          test -s build/ssl/libssl.a
          nm -g build/ssl/libssl.a | grep -E ' (_)?SSL_new$' > ssl-symbol
          test -s ssl-symbol
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/include" "$out/lib" "$out/share/licenses/boringssl"
          cp -R source/include/openssl "$out/include/"
          cp build/crypto/libcrypto.a build/ssl/libssl.a "$out/lib/"
          cp source/LICENSE "$out/share/licenses/boringssl/"
        '';
      }
    ];
  }
