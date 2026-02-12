# sbsigntools — UEFI Secure Boot signing tools
{ mkDerivation, fetchurl, sources, versions, make, openssl }:

mkDerivation {
  name = "sbsigntools-${versions.image-tools.sbsigntools}";
  version = versions.image-tools.sbsigntools;

  src = fetchurl {
    inherit (sources.sbsigntools) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd sbsigntools-${versions.image-tools.sbsigntools}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
    description = "sbsigntools — UEFI Secure Boot signing tools";
    homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git";
    license = "GPL-3.0-only";
  };
}
