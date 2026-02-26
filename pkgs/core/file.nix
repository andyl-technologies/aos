##! file — determine file type using magic numbers
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "5.46";
in
mkDerivation {
  pname = "file";
  inherit version;

  src = fetchurl {
    urls = [
      "https://astron.com/pub/file/file-${version}.tar.gz"
    ];
    hash = "sha256-ycx3x8VgxUMTXtxVWvYJ1WGdvvARmX6YjOQKPXXYYIg=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd file-${version}
      '';
    }
    {
      name = "build";
      script = ''
        $CONFIG_SHELL ./configure --prefix=$out
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
    description = "file — determine file type using magic numbers";
    homepage = "https://darwinsys.com/file/";
    license = "BSD-2-Clause";
  };
}
