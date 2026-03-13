##! strace — System call tracer for Linux
{
  mkDerivation,
  fetchurl,
  gnumake,
  linux-headers,
}:
let
  version = "6.12";
in
mkDerivation {
  pname = "strace";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/strace/strace/releases/download/v${version}/strace-${version}.tar.xz"
    ];
    hash = "sha256-xH2pO+RbYFX03HQdfyDvr1DKEBYKWxAMEJspT9nAvf4=";
  };

  buildDeps = [ gnumake linux-headers ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd strace-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-mpers \
          --enable-static=no
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
    description = "System call tracer for Linux";
    homepage = "https://strace.io/";
    license = "LGPL-2.1-or-later";
  };
}
