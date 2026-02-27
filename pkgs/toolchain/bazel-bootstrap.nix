##! Bazel bootstrap — pre-built binary for bootstrapping the from-source build
##!
##! Used only to vendor dependencies for the from-source Bazel build.
##! Not included in any system image.
{
  mkDerivation,
  fetchurl,
  lib,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk,
  gcc,
  binutils,
  grep,
  gzip,
  patch,
  diffutils,
  xz,
}: let
  version = "7.7.1";

  archFiles = {
    "x86_64-linux" = {
      url = "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel_nojdk-${version}-linux-x86_64";
      hash = "sha256-Rym9S7ZEPXeUDYDtWQPDIvJU9Q1SWqBrfcGI/9Hc6Xg=";
    };
    "aarch64-linux" = {
      url = "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel_nojdk-${version}-linux-arm64";
      hash = "sha256-8cFuQA/cSRzMBH5WicXoXkXSrO+s4QhdFgWq86UFQ4M=";
    };
  };

  files = archFiles.${lib.system} or (throw "bazel-bootstrap: unsupported system '${lib.system}'");
in
  mkDerivation {
    pname = "bazel-bootstrap";
    inherit version;

    src = fetchurl {
      urls = [files.url];
      hash = files.hash;
    };

    buildDeps = [];
    runtimeDeps = [
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk
      gcc
      binutils
      grep
      gzip
      patch
      diffutils
      xz
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib

          # Install and patch the raw binary
          cp $src $out/lib/bazel-real
          chmod u+wx $out/lib/bazel-real

          INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
          BT_LIB=$(dirname "$INTERP")
          STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
          STDCXX_DIR=""
          if [ -n "$STDCXX_FILE" ]; then
            STDCXX_DIR=$(dirname "$STDCXX_FILE")
          fi
          RPATH="$BT_LIB"
          if [ -n "$STDCXX_DIR" ]; then
            RPATH="$RPATH:$STDCXX_DIR"
          fi

          patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" \
                   $out/lib/bazel-real

          # Create wrapper script that provides PATH and JAVA_HOME
          cat > $out/bin/bazel << WRAPPER
          #!${bash}/bin/bash
          export PATH="${bash}/bin:${coreutils}/bin:${which}/bin:${zip}/bin:${unzip}/bin:${gawk}/bin:${python3}/bin:${gcc}/bin:${binutils}/bin:${grep}/bin:${gzip}/bin:${patch}/bin:${diffutils}/bin:${xz}/bin:\$PATH"
          export JAVA_HOME="${openjdk}"
          exec $out/lib/bazel-real "\$@"
          WRAPPER
          chmod +x $out/bin/bazel
        '';
      }
    ];

    meta = {
      description = "Bazel bootstrap — pre-built binary for bootstrapping";
      homepage = "https://bazel.build";
      license = "Apache-2.0";
    };
  }
