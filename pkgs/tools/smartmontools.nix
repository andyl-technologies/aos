##! smartmontools — S.M.A.R.T. disk monitoring tools (smartctl, smartd)
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
}: let
  version = "7.4";
in
  mkDerivation {
    pname = "smartmontools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/smartmontools/files/smartmontools/${version}/smartmontools-${version}.tar.gz"
      ];
      hash = "sha256-6aYfZB/5bKlTGe37F5SM0pfQzTNCc2ssScmdRxb7mT0=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of smartctl/smartd's
    # `--version` strings (which previously pinned xz-5.6.4 and the entire
    # live-bootstrap chain into the closure).
    disallowedReferences = [
      gnumake
      pkg-config
      patch
      patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd smartmontools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --without-systemdsystemunitdir \
            --without-nvme-devicescan
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
      description = "S.M.A.R.T. disk monitoring tools (smartctl, smartd)";
      homepage = "https://www.smartmontools.org/";
      license = "GPL-2.0-or-later";
    };
  }
