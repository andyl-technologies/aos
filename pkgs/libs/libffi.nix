##! libffi — Foreign Function Interface library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.5.2";
in
  mkDerivation {
    pname = "libffi";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libffi/libffi/releases/download/v${version}/libffi-${version}.tar.gz"
        "https://gcc.gnu.org/pub/libffi/libffi-${version}.tar.gz"
      ];
      hash = "sha256-86MIKiOzfCk6T80QUxR7Nx8v+R+n6hsqUuM1Z2usgtw=";
    };

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
