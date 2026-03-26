##! procps-ng — Process monitoring utilities (ps, top, free, vmstat, etc.)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  ncurses,
}:
let
  version = "4.0.5";
in
mkDerivation {
  pname = "procps-ng";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-${version}.tar.xz"
    ];
    hash = "sha256-wubRk8x4+EzW3bcqr21capFi8EcOWZIJIFf1/1GFYvo=";
  };

  buildDeps = [ gnumake pkg-config ];
  runtimeDeps = [ ncurses ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd procps-ng-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --disable-modern-top \
          --disable-kill \
          --without-systemd \
          --with-ncurses
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
    description = "Process monitoring utilities (ps, top, free, vmstat, etc.)";
    homepage = "https://gitlab.com/procps-ng/procps";
    license = "GPL-2.0-or-later";
  };
}
