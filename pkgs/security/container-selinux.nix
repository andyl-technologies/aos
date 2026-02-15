##! container-selinux — SELinux policy for container runtimes
{
  mkDerivation,
  fetchurl,
  make,
  m4,
  checkpolicy,
  semodule-utils,
  refpolicy,
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
    m4
    checkpolicy
    semodule-utils
    refpolicy
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
        # Use the patched refpolicy devel Makefile for module compilation
        make -f ${refpolicy}/usr/share/selinux/refpolicy/include/Makefile \
          container.pp
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/share/selinux/packages
        install -m 644 container.pp $out/share/selinux/packages/
        install -m 644 container.if $out/share/selinux/packages/ 2>/dev/null || true
        install -m 644 container.te $out/share/selinux/packages/ 2>/dev/null || true
        install -m 644 container.fc $out/share/selinux/packages/ 2>/dev/null || true
      '';
    }
  ];

  meta = {
    description = "container-selinux — SELinux policy module for container runtimes";
    homepage = "https://github.com/containers/container-selinux";
    license = "GPL-2.0-or-later";
  };
}
