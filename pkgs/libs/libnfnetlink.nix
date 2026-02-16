##! libnfnetlink — Low-level netfilter netlink communication library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.0.2";
in
mkDerivation {
  pname = "libnfnetlink";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-${version}.tar.bz2"
    ];
    hash = "sha256-sGTHw9Qm77R4bmCo5oWbgu4vLF5J/+6mQM/k/jPLw3Y=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libnfnetlink-${version}
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
    description = "libnfnetlink — low-level library for netfilter kernel/userspace communication";
    homepage = "https://www.netfilter.org/projects/libnfnetlink/";
    license = "GPL-2.0-only";
  };
}
