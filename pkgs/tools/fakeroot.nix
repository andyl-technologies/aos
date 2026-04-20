##! fakeroot — Give a fake root environment through LD_PRELOAD
{
  mkDerivation,
  fetchurl,
  gnumake,
  sed,
  coreutils,
  util-linux,
  libcap,
}:
let
  version = "1.37.2";
in
mkDerivation {
  pname = "fakeroot";
  inherit version;

  src = fetchurl {
    urls = [
      "https://deb.debian.org/debian/pool/main/f/fakeroot/fakeroot_${version}.orig.tar.gz"
    ];
    hash = "sha256-Dupg++iXcbiPz0Fcjy8KbM/p7eu887pdwCEnGNmIhNs=";
  };

  buildDeps = [gnumake];
  runtimeDeps = [libcap];
  propagatedDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd fakeroot-${version}
      '';
    }
    {
      name = "patch";
      script = ''
        # Hardcode paths to runtime tools in the fakeroot wrapper script
        # so it doesn't rely on PATH resolution at runtime.
        sed -i \
          -e 's|getopt|${util-linux}/bin/getopt|g' \
          -e 's|sed |${sed}/bin/sed |g' \
          -e 's|kill |${coreutils}/bin/kill |g' \
          -e 's|/bin/ls|${coreutils}/bin/ls|g' \
          -e 's|cut |${coreutils}/bin/cut |g' \
          scripts/fakeroot.in
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-ipc=sysv
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
    description = "fakeroot — give a fake root environment through LD_PRELOAD";
    homepage = "https://salsa.debian.org/clint/fakeroot";
    license = "GPL-2.0-or-later";
  };
}
