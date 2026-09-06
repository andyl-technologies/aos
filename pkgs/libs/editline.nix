##! editline — Small line editing library (troglobit editline)
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  ncurses,
}: let
  upstream = mkGithubUpstream {
    unitId = "editline-2";
    family = "editline";
    stream = "2";
    owner = "pkgs/libs/editline.nix";
    version = "2.1.0";
    upstreamId = "2.1.0";
    repository = "troglobit/editline";
    provider = "github-releases";
    tagPrefix = "";
    major = 2;
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
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-GJ4XklPAky0VzpT1Pozeegw4OD858R87ktQM0Yg5Z48=";
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
