# SELinux Reference Policy
{ mkDerivation, fetchurl, sources, versions, make, policycoreutils }:

mkDerivation {
  name = "refpolicy-${versions.security.refpolicy}";
  version = versions.security.refpolicy;

  src = fetchurl {
    inherit (sources.refpolicy) url hash;
  };

  buildDeps = [ make policycoreutils ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd refpolicy-${versions.security.refpolicy}
      '';
    }
    { name = "configure";
      script = ''
        # Set policy build options
        sed -i \
          -e 's/^#\?DISTRO.*/DISTRO = redhat/' \
          -e 's/^#\?UBAC.*/UBAC = y/' \
          -e 's/^#\?DIRECT_INITRC.*/DIRECT_INITRC = n/' \
          -e 's/^#\?MONOLITHIC.*/MONOLITHIC = n/' \
          -e 's|^#\?PREFIX.*|PREFIX = '"$out"'|' \
          build.conf
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out
      '';
    }
  ];

  meta = {
    description = "SELinux Reference Policy — base SELinux policy";
    homepage = "https://github.com/SELinuxProject/refpolicy";
    license = "GPL-2.0-or-later";
  };
}
