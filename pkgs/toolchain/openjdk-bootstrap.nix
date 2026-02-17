##! OpenJDK bootstrap — pre-built Adoptium Temurin JDK for bootstrapping
{
  mkDerivation,
  fetchurl,
  lib,
}:
let
  version = "21.0.10";
  build = "7";

  archFiles = {
    "x86_64-linux" = {
      url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${version}%2B${build}/OpenJDK21U-jdk_x64_linux_hotspot_${version}_${build}.tar.gz";
      hash = "sha256-6jub1GTW3SU+mnrM9Z98zSo25KppZAtyUeM3DK74lqQ=";
    };
    "aarch64-linux" = {
      url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${version}%2B${build}/OpenJDK21U-jdk_aarch64_linux_hotspot_${version}_${build}.tar.gz";
      hash = "sha256-NX/uKfsNXAefZzDbmLKJQt8Tpu7UJvbGHNStcDqye5o=";
    };
  };

  files = archFiles.${lib.system} or (throw "openjdk-bootstrap: unsupported system '${lib.system}'");
in
mkDerivation {
  pname = "openjdk-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [ files.url ];
    hash = files.hash;
  };

  buildDeps = [ ];
  runtimeDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        cp -a jdk-${version}+${build}/* $out/

        # Patch ELF binaries with the correct dynamic linker and rpath
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        BT_LIB=$(dirname "$INTERP")

        # Patch executables: set interpreter and rpath
        for f in $out/bin/* $out/lib/jspawnhelper; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" \
                     --set-rpath "$out/lib:$out/lib/server:$BT_LIB" \
                     "$f" 2>/dev/null || true
          fi
        done

        # Patch shared libraries: set rpath only (no interpreter)
        find $out/lib -name '*.so' -o -name '*.so.*' | while read f; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-rpath "$out/lib:$out/lib/server:$BT_LIB" \
                     "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "OpenJDK bootstrap — pre-built Adoptium Temurin for compiler bootstrapping";
    homepage = "https://adoptium.net";
    license = "GPL-2.0-with-classpath-exception";
  };
}
