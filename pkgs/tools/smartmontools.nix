##! smartmontools — S.M.A.R.T. disk monitoring tools (smartctl, smartd)
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  bash,
  coreutils,
  curl,
  gnupg,
  sed,
  stdenv,
  buildPackages,
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
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash coreutils curl gnupg sed]
      else [];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of smartctl/smartd's
    # `--version` strings (which previously pinned xz-5.6.4 and the entire
    # live-bootstrap chain into the closure).
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
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
            $configureFlags \
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            updateScript="$out/sbin/update-smart-drivedb"
            if [ -f "$updateScript" ]; then
              sed -i \
                -e "1s|^#!.*|#!${bash}/bin/bash|" \
                -e "s|^export PATH=.*|export PATH=\"${curl}/bin:${gnupg}/bin:${coreutils}/bin:${sed}/bin\"|" \
                "$updateScript"
            fi
          ''
          else ''
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
