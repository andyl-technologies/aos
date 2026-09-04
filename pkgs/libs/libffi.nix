##! libffi — Foreign Function Interface library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "libffi-3";
    family = "libffi";
    stream = "3";
    owner = "pkgs/libs/libffi.nix";
    version = "3.5.2";
    upstreamId = "v3.5.2";
    repository = "libffi/libffi";
    tagPrefix = "v";
    major = 3;
    source = {
      urlTemplates = [
        {
          scheme = "https";
          authority = "github.com";
          path = [
            "libffi"
            "libffi"
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
                {literal = "libffi-";}
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
        }
        {
          scheme = "https";
          authority = "gcc.gnu.org";
          path = [
            "pub"
            "libffi"
            {
              parts = [
                {literal = "libffi-";}
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
        }
      ];
      hash = "sha256-86MIKiOzfCk6T80QUxR7Nx8v+R+n6hsqUuM1Z2usgtw=";
      allowedRedirectHosts = ["gcc.gnu.org" "github.com" "release-assets.githubusercontent.com"];
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libffi";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libffi-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --disable-docs
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
          # libffi installs to lib64/ on x86_64 — move to lib/ for AOS conventions
          if [ -d "$out/lib64" ]; then
            cp -a "$out/lib64/"* "$out/lib/"
            rm -rf "$out/lib64"
          fi
          # Some packages look for libffi headers in include/ not lib/libffi-*/include/
          if [ -d "$out/lib/libffi-${version}/include" ]; then
            cp -n "$out/lib/libffi-${version}/include/"*.h "$out/include/" 2>/dev/null || true
          fi
        '';
      }
    ];

    meta = {
      description = "libffi — a portable foreign function interface library";
      homepage = "https://sourceware.org/libffi/";
      license = "MIT";
    };
  }
