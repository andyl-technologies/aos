##! SELinux Reference Policy
{
  mkDerivation,
  fetchurl,
  make,
  m4,
  python3,
  util-linux,
  checkpolicy,
  semodule-utils,
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
    m4
    python3
    util-linux
    checkpolicy
    semodule-utils
    policycoreutils
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        # The release tarball may extract as "refpolicy" or "refpolicy-${version}"
        if [ -d refpolicy-${version} ]; then
          cd refpolicy-${version}
        elif [ -d refpolicy ]; then
          cd refpolicy
        else
          cd "$(ls -d */ | head -1)"
        fi
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

        # Override individual tool paths in the Makefile.
        # checkmodule/checkpolicy come from the checkpolicy package,
        # semodule_package/semodule_link/semodule_expand from semodule-utils,
        # and semodule/load_policy/setfiles/sefcontext_compile from policycoreutils.
        sed -i \
          -e 's|^CHECKPOLICY ?=.*|CHECKPOLICY := ${checkpolicy}/bin/checkpolicy|' \
          -e 's|^CHECKMODULE ?=.*|CHECKMODULE := ${checkpolicy}/bin/checkmodule|' \
          -e 's|^SEMOD_PKG ?=.*|SEMOD_PKG := ${semodule-utils}/bin/semodule_package|' \
          -e 's|^SEMOD_LNK ?=.*|SEMOD_LNK := ${semodule-utils}/bin/semodule_link|' \
          -e 's|^SEMOD_EXP ?=.*|SEMOD_EXP := ${semodule-utils}/bin/semodule_expand|' \
          -e 's|^SEMODULE ?=.*|SEMODULE := ${policycoreutils}/sbin/semodule|' \
          -e 's|^LOADPOLICY ?=.*|LOADPOLICY := ${policycoreutils}/sbin/load_policy|' \
          -e 's|^SETFILES ?=.*|SETFILES := ${policycoreutils}/sbin/setfiles|' \
          -e 's|^SEFCONTEXT_COMPILE ?=.*|SEFCONTEXT_COMPILE := ${policycoreutils}/sbin/sefcontext_compile|' \
          Makefile
      '';
    }
    {
      name = "build";
      script = ''
        # Generate modules.conf with all modules enabled
        make conf
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install DESTDIR=$out
        make install-headers DESTDIR=$out

        # Patch the installed devel Makefile to use store paths instead
        # of hardcoded /usr and /etc paths
        DEVMK=$out/usr/share/selinux/refpolicy/include/Makefile
        sed -i \
          -e 's|^NAME ?=.*|NAME := refpolicy|' \
          -e 's|^SHAREDIR ?=.*|SHAREDIR := '"$out"'/usr/share/selinux|' \
          -e 's|^PREFIX :=.*|PREFIX := '"$out"'/usr|' \
          -e 's|^BINDIR :=.*|BINDIR := ${checkpolicy}/bin|' \
          -e 's|^SBINDIR :=.*|SBINDIR := ${policycoreutils}/sbin|' \
          -e 's|^CHECKMODULE :=.*|CHECKMODULE := ${checkpolicy}/bin/checkmodule|' \
          -e 's|^SEMODULE :=.*|SEMODULE := ${policycoreutils}/sbin/semodule|' \
          -e 's|^SEMOD_PKG :=.*|SEMOD_PKG := ${semodule-utils}/bin/semodule_package|' \
          "$DEVMK"
      '';
    }
  ];

  meta = {
    description = "SELinux Reference Policy — base SELinux policy";
    homepage = "https://github.com/SELinuxProject/refpolicy";
    license = "GPL-2.0-or-later";
  };
}
