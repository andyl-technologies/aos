# ipvsadm — IPVS administration utility
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "ipvsadm-${versions.kubernetes.ipvsadm}";
  version = versions.kubernetes.ipvsadm;

  src = fetchurl {
    inherit (sources.ipvsadm) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd ipvsadm-${versions.kubernetes.ipvsadm}
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SBIN=$out/sbin -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
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
