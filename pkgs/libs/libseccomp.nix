##! libseccomp — Seccomp (secure computing) userspace library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  gperf,
}: let
  upstream = mkGithubUpstream {
    unitId = "libseccomp-2";
    family = "libseccomp";
    stream = "2";
    owner = "pkgs/libs/libseccomp.nix";
    version = "2.6.0";
    upstreamId = "v2.6.0";
    repository = "seccomp/libseccomp";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    riskFloor = "high";
    source = {
      authority = "github.com";
      path = [
        "seccomp"
        "libseccomp"
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
            {literal = "libseccomp-";}
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
      hash = "sha256-g7YIUjLRWIw3ncm5yuR7s3QHzyYubnSZPGG6ctKnhNw=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libseccomp";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      gnumake
      gperf
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libseccomp-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
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
      description = "libseccomp — enhanced seccomp (mode 2) userspace library";
      homepage = "https://github.com/seccomp/libseccomp";
      license = "LGPL-2.1-only";
    };
  }
