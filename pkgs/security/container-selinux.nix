# container-selinux — SELinux policy for container runtimes
{
  mkDerivation,
  fetchurl,
  make,
  policycoreutils,
}:

let
  version = "2.232.1";
in
mkDerivation {
  pname = "container-selinux";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/containers/container-selinux/archive/v${version}/container-selinux-${version}.tar.gz"
    ];
    hash = "sha256-puK6O4twbnNP3Y3r8NW/HZuDkvTCGtJg0US0yE4I48o=";
  };

  buildDeps = [
    make
    policycoreutils
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd container-selinux-${version}
      '';
    }
    {
      name = "build";
      script = ''
        make -f /usr/share/selinux/devel/Makefile container.pp 2>/dev/null || \
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/share/selinux/packages
        mkdir -p $out/share/containers
        cp -a *.pp $out/share/selinux/packages/ 2>/dev/null || true
        cp -a container.if $out/share/selinux/packages/ 2>/dev/null || true
        cp -a container.te $out/share/selinux/packages/ 2>/dev/null || true
      '';
    }
  ];

  meta = {
    description = "container-selinux — SELinux policy module for container runtimes";
    homepage = "https://github.com/containers/container-selinux";
    license = "GPL-2.0-or-later";
  };
}
