##! conntrack-tools — Connection tracking userspace tools
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
  libnetfilter_queue,
  libnetfilter_cttimeout,
  libnetfilter_cthelper,
  libtirpc,
  systemd,
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
      libnetfilter_queue
      libnetfilter_cttimeout
      libnetfilter_cthelper
      libtirpc
      systemd
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
            --enable-systemd
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
      description = "conntrack-tools — userspace connection tracking tools";
      homepage = "https://www.netfilter.org/projects/conntrack-tools/";
      license = "GPL-2.0-or-later";
    };
  }
