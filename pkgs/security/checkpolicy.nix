##! checkpolicy — SELinux policy compiler and module compiler
{
  mkDerivation,
  fetchurl,
  make,
  flex,
  bison,
  libsepol,
  libselinux,
}:

let
  version = "3.7";
in
mkDerivation {
  pname = "checkpolicy";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
    ];
    hash = "sha256-pZdVqeMfrvEKaNOscWmlx6ubI742J7Z1pcOECgXYKS4=";
  };

  buildDeps = [
    make
    flex
    bison
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
        cd selinux-${version}/checkpolicy
      '';
    }
    {
      name = "build";
      script = ''
        make PREFIX=$out BINDIR=$out/bin \
          -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install PREFIX=$out BINDIR=$out/bin
      '';
    }
  ];

  meta = {
    description = "checkpolicy — SELinux policy compiler (checkpolicy, checkmodule)";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "GPL-2.0-or-later";
  };
}
