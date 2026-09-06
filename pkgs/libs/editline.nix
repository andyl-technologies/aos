##! editline — Small line editing library (troglobit editline)
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  ncurses,
}: let
  upstream = mkGithubUpstream {
    unitId = "editline-1";
    family = "editline";
    stream = "1";
    owner = "pkgs/libs/editline.nix";
    version = "1.17.1";
    upstreamId = "1.17.1";
    repository = "troglobit/editline";
    provider = "github-releases";
    tagPrefix = "";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "troglobit"
        "editline"
        "releases"
        "download"
        {
          parts = [
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
            {literal = "editline-";}
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
      hash = "sha256-3yI7MzOlRf3bxntJ3tPSQsZvrfegS+s62iCVf80f/A4=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "editline";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd editline-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
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
      description = "editline — small line editing library";
      homepage = "https://github.com/troglobit/editline";
      license = "ISC";
    };
  }
