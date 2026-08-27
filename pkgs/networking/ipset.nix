##! pkgs/networking/ipset.nix — IP set framework userspace tool
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "7.24";
in
  mkDerivation {
    pname = "ipset";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ipset.netfilter.org/ipset-${version}.tar.bz2"
      ];
      hash = "sha256-++NCTf8iLBy15cNNOLZFJLIhfOgCJsFP3LsTsp6jYRI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libmnl
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ipset-${version}
        '';
      }
      {
        name = "configure";
        # `--with-kmod=no` skips the in-tree kernel-module build —
        # ipset's tarball ships its own copy of the kernel modules
        # and would otherwise try to invoke a kbuild from here. We
        # get the modules from the AOS kernel package instead (see
        # pkgs/kernel/config/networking.config).
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static \
            --with-kmod=no
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
      description = "ipset — administration tool for IP sets";
      homepage = "https://ipset.netfilter.org/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-ipset";
        tool = self;
        # `ipset help` works without root and without kernel modules
        # loaded. We rely on the kernel-side check (kconfig in
        # pkgs/kernel/config/networking.config) to cover the `ipset
        # list / create` paths that need an ip_set kmod present.
        command = "ipset help";
      };
    };
  }
