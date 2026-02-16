##! libnetfilter_queue — Userspace API to packets queued by the kernel packet filter
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libmnl,
  libnfnetlink,
}:

let
  version = "1.0.5";
in
mkDerivation {
  pname = "libnetfilter_queue";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-${version}.tar.bz2"
    ];
    hash = "sha256-+f88ETBdbgPYFAWVe9wRrqGODTFcPj9I2lOiS6JRufU=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [
    libmnl
    libnfnetlink
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libnetfilter_queue-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-static \
          --enable-shared
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
    description = "libnetfilter_queue — userspace API to packets queued by the kernel packet filter";
    homepage = "https://www.netfilter.org/projects/libnetfilter_queue/";
    license = "GPL-2.0-only";
  };
}
