##! ipvsadm — IPVS administration utility
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libnl,
  popt,
}: let
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

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libnl
      popt
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ipvsadm-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # Replace hardcoded -lnl with pkg-config flags for libnl-genl-3.0
          NL_LIBS=$(pkg-config --libs libnl-genl-3.0)
          sed "s|-lnl|$NL_LIBS|g" Makefile > Makefile.tmp
          mv Makefile.tmp Makefile
        '';
      }
      {
        name = "build";
        script = ''
          make \
            PREFIX=$out \
            SBIN=$out/sbin \
            MANDIR=share/man \
            INCLUDE="$(pkg-config --cflags libnl-genl-3.0)"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/sbin $out/share/man/man8
          make install \
            PREFIX=$out \
            SBIN=$out/sbin \
            MANDIR=share/man \
            BUILD_ROOT=$out
        '';
      }
    ];

    meta = {
      description = "ipvsadm — administration tool for Linux Virtual Server (IPVS)";
      homepage = "https://mirrors.kernel.org/pub/linux/utils/kernel/ipvsadm/";
      license = "GPL-2.0-or-later";
    };
  }
