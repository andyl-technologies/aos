##! libxcrypt — Extended crypt library for DES/MD5/SHA/Blowfish password hashing
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  perl,
}: let
  upstream = mkGithubUpstream {
    unitId = "libxcrypt-4";
    family = "libxcrypt";
    stream = "4";
    owner = "pkgs/libs/libxcrypt.nix";
    version = "4.5.2";
    upstreamId = "v4.5.2";
    repository = "besser82/libxcrypt";
    tagPrefix = "v";
    major = 4;
    source = {
      authority = "github.com";
      path = [
        "besser82"
        "libxcrypt"
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
            {literal = "libxcrypt-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.xz";}
          ];
        }
      ];
      hash = "sha256-cVE6McAaQovM1TZ6Mv2V8RXW2sUPtbYMd51ceUKuwHE=";
    };
    riskFloor = "high";
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libxcrypt";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      gnumake
      perl
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libxcrypt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-hashes=strong,glibc \
            --enable-obsolete-api=no \
            --disable-failure-tokens \
            --disable-static
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
      description = "libxcrypt — extended crypt library for password hashing";
      homepage = "https://github.com/besser82/libxcrypt";
      license = "LGPL-2.1-or-later";
    };
  }
