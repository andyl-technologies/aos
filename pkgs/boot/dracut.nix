# dracut — initramfs infrastructure
{ mkDerivation, fetchurl, make, pkg-config,
  bash, coreutils, kmod, util-linux, systemd }:

let version = "103"; in
mkDerivation {
  pname = "dracut";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/dracut-ng/dracut-ng/archive/${version}/dracut-${version}.tar.gz"
    ];
    hash = "sha256-mpK08GQ5JqZRYhcdaLlSX8k+boL0VaSzk42zhahBvag=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ bash coreutils kmod util-linux systemd ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd dracut-ng-${version}
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
