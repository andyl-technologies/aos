##! Shared builder for intermediate OpenJDK bootstrap compilers.
##! Underscore prefix = not auto-discovered. Imported by openjdk-N.nix files.
{
  fetchurl,
  mkDerivation,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
}:
{
  major,
  version,
  build,
  srcHash,
  prevJdk,
  repoSuffix ? "u",
  extraConfigureFlags ? [ ],
  extraBuildDeps ? [ ],
  extraPatches ? [ ],
}:
let
  tag = "jdk-${version}+${build}";
  repo = "jdk${toString major}${repoSuffix}";
  extraCfgStr = builtins.concatStringsSep " " extraConfigureFlags;
in
mkDerivation {
  pname = "openjdk-${toString major}";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/openjdk/${repo}/archive/refs/tags/${tag}.tar.gz"
    ];
    hash = srcHash;
  };

  buildDeps = [
    gnumake
    autoconf
    bash
    which
    zip
    unzip
    gawk
    coreutils
    binutils
    file
    xorg-stubs
  ]
  ++ extraBuildDeps;
  runtimeDeps = [
    zlib
    fontconfig
    freetype
  ];

  patches = extraPatches;

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jdk*-*
      '';
    }
    {
      name = "configure";
      script = ''
        $CONFIG_SHELL configure \
          --with-boot-jdk=${prevJdk} \
          --enable-headless-only \
          --with-native-debug-symbols=none \
          --disable-warnings-as-errors \
          --with-zlib=system \
          --with-libjpeg=bundled \
          --with-giflib=bundled \
          --with-libpng=bundled \
          --with-lcms=bundled \
          --with-cups-include=${cups}/include \
          --with-alsa=${alsa-lib} \
          --with-freetype-include=${freetype}/include/freetype2 \
          --with-freetype-lib=${freetype}/lib \
          --x-includes=${xorg-stubs}/include \
          --x-libraries=${xorg-stubs}/lib \
          --with-version-build=${build} \
          --with-version-opt=aos \
          --with-version-pre= \
          --with-extra-cflags="-Wno-error" \
          --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
          --with-jobs=$NIX_BUILD_CORES \
          ${extraCfgStr}
      '';
    }
    {
      name = "build";
      script = ''
        make images JOBS=$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        cp -a build/*/images/jdk/* $out/

        # Patch ELF binaries with the correct dynamic linker and rpath
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        BT_LIB=$(dirname "$INTERP")

        # Find libstdc++ directory (nested under lib/gcc/...)
        STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
        STDCXX_DIR=""
        if [ -n "$STDCXX_FILE" ]; then
          STDCXX_DIR=$(dirname "$STDCXX_FILE")
        fi
        RPATH="$out/lib:$out/lib/server:$BT_LIB"
        if [ -n "$STDCXX_DIR" ]; then
          RPATH="$RPATH:$STDCXX_DIR"
        fi

        # Patch executables
        for f in $out/bin/* $out/lib/jspawnhelper; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" \
                     --set-rpath "$RPATH" \
                     "$f" 2>/dev/null || true
          fi
        done

        # Patch shared libraries
        find $out/lib -name '*.so' -o -name '*.so.*' | while read f; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-rpath "$RPATH" \
                     "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "OpenJDK ${toString major} — bootstrap chain intermediate";
    homepage = "https://openjdk.org";
    license = "GPL-2.0-with-classpath-exception";
  };
}
