##! iproute2 — Linux networking utilities
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
  bison,
  flex,
}:
let
  version = "6.18.0";
in
mkDerivation {
  pname = "iproute2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.kernel.org/pub/linux/utils/net/iproute2/iproute2-${version}.tar.xz"
    ];
    hash = "sha256-a6Ug4ZdeTFDckx7q6R6jfBmLihc3RIhfiJW4QyX51FY=";
  };

  buildDeps = [
    gnumake
    pkg-config
    bison
    flex
  ];
  runtimeDeps = [ libmnl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd iproute2-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure --prefix=$out
      '';
    }
    {
      name = "build";
      script = ''
        make PREFIX=$out SBINDIR=$out/sbin -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install PREFIX=$out SBINDIR=$out/sbin
      '';
    }
  ];

  meta = {
    description = "iproute2 — Linux networking and traffic control utilities";
    homepage = "https://wiki.linuxfoundation.org/networking/iproute2";
    license = "GPL-2.0-or-later";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-iproute2";
        tool = self;
        command = "ip -V 2>&1";
      };
    };
}
