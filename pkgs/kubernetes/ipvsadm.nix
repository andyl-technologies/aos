# ipvsadm — IPVS administration utility
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.31";
in
mkDerivation {
  pname = "ipvsadm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.kernel.org/pub/linux/utils/kernel/ipvsadm/ipvsadm-${version}.tar.xz"
    ];
    hash = "sha256-GgpeJbWhImQ10vt2NBZW+DpxAYOuuw0gTbOcDsO+39s=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd ipvsadm-${version}
      '';
    }
    {
      name = "build";
      script = ''
        make PREFIX=$out SBIN=$out/sbin -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/sbin $out/share/man/man8
        make install PREFIX=$out SBIN=$out/sbin
      '';
    }
  ];

  meta = {
    description = "ipvsadm — administration tool for Linux Virtual Server (IPVS)";
    homepage = "https://mirrors.kernel.org/pub/linux/utils/kernel/ipvsadm/";
    license = "GPL-2.0-or-later";
  };
}
