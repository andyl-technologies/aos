##! SETools — SELinux policy analysis tools
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libsepol,
  libselinux,
}:

let
  version = "4.5.1";
in
mkDerivation {
  pname = "setools";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/setools/releases/download/${version}/setools-${version}.tar.bz2"
    ];
    hash = "sha256-JeR9ALv/1gRvVUCcm6OwjZsdV4jMFZ6iR9ngztjkguc=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [
    libsepol
    libselinux
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd setools-${version}
      '';
    }
    {
      name = "build";
      script = ''
        # setools uses a Python/Cython build system
        export CFLAGS="-I${libsepol}/include -I${libselinux}/include"
        export LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib"
        python3 setup.py build
      '';
    }
    {
      name = "install";
      script = ''
        python3 setup.py install --prefix=$out --optimize=1
      '';
    }
  ];

  meta = {
    description = "SETools — policy analysis tools for SELinux";
    homepage = "https://github.com/SELinuxProject/setools";
    license = "GPL-2.0-or-later";
  };
}
