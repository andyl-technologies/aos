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
  openjdk-21,
  gcc,
  binutils,
  grep,
  gzip,
  patch,
  diffutils,
  xz,
  bootstrapTools,
  gcc-libs,
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
      openjdk-21
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

          # Install the pre-built binary as-is (DO NOT patchelf — it corrupts
          # this binary and causes segfaults in the dynamic linker)
          cp $src $out/lib/bazel-real
          chmod u+wx $out/lib/bazel-real

          INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
          BT_LIB=$(dirname "$INTERP")

          # Compile a tiny LD_PRELOAD library that intercepts
          # readlink("/proc/self/exe") to return the real bazel binary path.
          # Without this, invoking via explicit ld.so makes /proc/self/exe
          # point to the dynamic linker, and Bazel (a self-extracting zip)
          # tries to open ld.so as a zip file.
          cat > /tmp/proc_self_exe_fix.c << 'CSRC'
          #define _GNU_SOURCE
          #include <dlfcn.h>
          #include <string.h>
          #include <stdlib.h>
          #include <unistd.h>
          typedef ssize_t (*readlink_fn_t)(const char *, char *, size_t);
          ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
              readlink_fn_t real_readlink = (readlink_fn_t)dlsym(RTLD_NEXT, "readlink");
              if (strcmp(pathname, "/proc/self/exe") == 0) {
                  const char *p = getenv("BAZEL_REAL_PATH");
                  if (p) {
                      size_t len = strlen(p);
                      if (len > bufsiz) len = bufsiz;
                      memcpy(buf, p, len);
                      return (ssize_t)len;
                  }
              }
              return real_readlink(pathname, buf, bufsiz);
          }
          CSRC
          cc -shared -fPIC -o $out/lib/proc_self_exe_fix.so \
            /tmp/proc_self_exe_fix.c -ldl

          # Create wrapper script
          cat > $out/bin/bazel << WRAPPER
          #!${bash}/bin/bash
          export PATH="${bash}/bin:${coreutils}/bin:${which}/bin:${zip}/bin:${unzip}/bin:${gawk}/bin:${python3}/bin:${gcc}/bin:${binutils}/bin:${grep}/bin:${gzip}/bin:${patch}/bin:${diffutils}/bin:${xz}/bin:\$PATH"
          export JAVA_HOME="${openjdk-21}"
          export LD_LIBRARY_PATH="${gcc-libs}/lib:$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
          export BAZEL_REAL_PATH="$out/lib/bazel-real"
          export LD_PRELOAD="$out/lib/proc_self_exe_fix.so''${LD_PRELOAD:+:\$LD_PRELOAD}"
          exec $INTERP $out/lib/bazel-real "\$@"
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
