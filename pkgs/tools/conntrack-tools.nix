##! conntrack-tools — Connection tracking userspace tools for netfilter
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnetfilter_cthelper,
  libnetfilter_cttimeout,
  libnetfilter_queue,
  libtirpc,
}: let
  version = "1.4.8";
in
  mkDerivation {
    pname = "conntrack-tools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-${version}.tar.xz"
      ];
      hash = "sha256-BnZ39MX2VkgZ547TqdSomAk16pJz86uyKkIOowq13tY=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
      libnetfilter_conntrack
      libnetfilter_cthelper
      libnetfilter_cttimeout
      libnetfilter_queue
      libtirpc
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd conntrack-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static
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
      description = "conntrack-tools — connection tracking userspace tools for netfilter";
      homepage = "https://www.netfilter.org/projects/conntrack-tools/";
      license = "GPL-2.0-or-later";
    };
  }
