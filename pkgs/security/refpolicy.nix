# SELinux Reference Policy
{
  mkDerivation,
  fetchurl,
  make,
  policycoreutils,
}:

let
  version = "2.20240916";
in
mkDerivation {
  pname = "refpolicy";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20240916/refpolicy-${version}.tar.bz2"
    ];
    hash = "sha256-pOOQcqyRvwkqCGYLJGpJ8+mGyiwWQCpbH60643To10c=";
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
        cd refpolicy-${version}
      '';
    }
    {
      name = "configure";
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
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
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
