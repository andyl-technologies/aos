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
        # Fix shebangs for sandbox
        for f in $(find . -type f -name '*.sh' -o -name 'configure'); do
          if head -1 "$f" | grep -q '^#!'; then
            sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
            sed -i "1s|#!/usr/bin/env bash|#!$CONFIG_SHELL|" "$f"
            sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
          fi
        done

        $CONFIG_SHELL ./configure \
          --prefix=/ \
          --sysconfdir=/etc \
          --systemdsystemunitdir=/lib/systemd/system \
          --bashcompletiondir=/share/bash-completion/completions \
          --disable-documentation
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install DESTDIR=$out
      '';
    }
  ];

  meta = {
    description = "dracut — event-driven initramfs infrastructure";
    homepage = "https://github.com/dracut-ng/dracut-ng";
    license = "GPL-2.0-or-later";
  };
}
