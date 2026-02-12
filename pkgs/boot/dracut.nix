# dracut — initramfs infrastructure
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  bash, coreutils, kmod, util-linux, systemd }:

mkDerivation {
  name = "dracut-${versions.init.dracut}";
  version = versions.init.dracut;

  src = fetchurl {
    inherit (sources.dracut) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ bash coreutils kmod util-linux systemd ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd dracut-ng-${versions.init.dracut}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
          --systemdsystemunitdir=$out/lib/systemd/system \
          --bashcompletiondir=$out/share/bash-completion/completions
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "dracut — event-driven initramfs infrastructure";
    homepage = "https://github.com/dracut-ng/dracut-ng";
    license = "GPL-2.0-or-later";
  };
}
