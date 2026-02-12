# container-selinux — SELinux policy for container runtimes
{ mkDerivation, fetchurl, sources, versions, make, policycoreutils }:

mkDerivation {
  name = "container-selinux-${versions.security.container-selinux}";
  version = versions.security.container-selinux;

  src = fetchurl {
    inherit (sources.container-selinux) url hash;
  };

  buildDeps = [ make policycoreutils ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd container-selinux-${versions.security.container-selinux}
      '';
    }
    { name = "build";
      script = ''
        make -f /usr/share/selinux/devel/Makefile container.pp 2>/dev/null || \
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
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
