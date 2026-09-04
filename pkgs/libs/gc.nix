##! gc — Boehm-Demers-Weiser conservative garbage collector
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
  lib,
  libatomic_ops,
}: let
  upstream = mkGithubUpstream {
    unitId = "gc-8";
    family = "gc";
    stream = "8";
    owner = "pkgs/libs/gc.nix";
    version = "8.2.12";
    upstreamId = "v8.2.12";
    repository = "ivmai/bdwgc";
    tagPrefix = "v";
    major = 8;
    source = {
      authority = "github.com";
      path = [
        "ivmai"
        "bdwgc"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "gc-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-QuUZStBqtv+4Bsg+uZwDRitJXZec2ngvPHLAivgzzU4=";
    };
    riskFloor = "normal";
  };
  inherit (upstream) version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  needsExternalAtomicOps = stdenv.isCross && stdenv.hostPlatform.isLinux;
in
  mkDerivation {
    pname = "gc";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = lib.optional needsExternalAtomicOps libatomic_ops;
    propagatedDeps = [];

    # The upstream compiler-intrinsics probe is an AC_RUN_IFELSE and is
    # unconditionally skipped while cross-compiling.  Darwin Clang provides
    # the required atomic builtins, so select that supported backend directly.
    configureFlags =
      if isDarwinCross
      then "--with-libatomic-ops=none"
      else "";

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd gc-${version}
          '';
        }
      ]
      ++ (
        if isDarwinCross
        then [
          {
            name = "darwin-libtool";
            script = ''
              # Libtool treats any -single_module diagnostic as rejection and
              # falls back to a relocatable C++ prelink.  Modern ld64 treats
              # single-module dylibs as the default and warns that the option
              # is obsolete, while ld64.lld intentionally does not implement
              # the fallback's `-r`.  Seed the successful semantic result so
              # Libtool uses its normal one-step Darwin dylib link.
              export lt_cv_apple_cc_single_mod=yes
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --enable-cplusplus \
              --enable-large-config \
              --enable-threads=posix
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
      description = "gc — Boehm-Demers-Weiser conservative garbage collector";
      homepage = "https://www.hboehm.info/gc/";
      license = "MIT";
    };
  }
