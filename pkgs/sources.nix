# ANDYL OS — All source URLs and integrity hashes.
# Hashes use the SRI format: sha256-<base64>.
# Placeholder hashes (AAAA...) will be backfilled by the prefetch tooling.
{
  # --- Toolchain ---
  gcc = {
    url = "mirror://gnu/gcc/gcc-13.3.0/gcc-13.3.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  glibc = {
    url = "mirror://gnu/glibc/glibc-2.39.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  binutils = {
    url = "mirror://gnu/binutils/binutils-2.42.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  linux-headers = {
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.11.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Core ---
  make = {
    url = "mirror://gnu/make/make-4.4.1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  coreutils = {
    url = "mirror://gnu/coreutils/coreutils-9.5.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  bash = {
    url = "mirror://gnu/bash/bash-5.2.32.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  findutils = {
    url = "mirror://gnu/findutils/findutils-4.10.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  gawk = {
    url = "mirror://gnu/gawk/gawk-5.3.1.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  grep = {
    url = "mirror://gnu/grep/grep-3.11.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  sed = {
    url = "mirror://gnu/sed/sed-4.9.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  tar = {
    url = "mirror://gnu/tar/tar-1.35.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  gzip = {
    url = "mirror://gnu/gzip/gzip-1.13.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  xz = {
    url = "https://github.com/tukaani-project/xz/releases/download/v5.6.0/xz-5.6.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  diffutils = {
    url = "mirror://gnu/diffutils/diffutils-3.10.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  patch = {
    url = "mirror://gnu/patch/patch-2.7.6.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  pkg-config = {
    url = "https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  perl = {
    url = "https://www.cpan.org/src/5.0/perl-5.38.2.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  bison = {
    url = "mirror://gnu/bison/bison-3.8.2.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  texinfo = {
    url = "mirror://gnu/texinfo/texinfo-7.1.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Compression ---
  zlib = {
    url = "https://zlib.net/zlib-1.3.1.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  zstd = {
    url = "https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  lz4 = {
    url = "https://github.com/lz4/lz4/releases/download/v1.9.4/lz4-1.9.4.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- TLS ---
  openssl = {
    url = "https://www.openssl.org/source/openssl-3.3.2.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Kernel ---
  linux = {
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.11.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  firmware = {
    url = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/snapshot/linux-firmware-20241210.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Security ---
  audit = {
    url = "https://people.redhat.com/sgrubb/audit/audit-4.0.2.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  selinux-userspace = {
    url = "https://github.com/SELinuxProject/selinux/releases/download/3.7/selinux-3.7.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  refpolicy = {
    url = "https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20240916/refpolicy-2.20240916.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  container-selinux = {
    url = "https://github.com/containers/container-selinux/archive/v2.232.1/container-selinux-2.232.1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  setools = {
    url = "https://github.com/SELinuxProject/setools/releases/download/4.5.1/setools-4.5.1.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Storage ---
  zfs = {
    url = "https://github.com/openzfs/zfs/releases/download/zfs-2.3.0/zfs-2.3.0.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Networking ---
  iproute2 = {
    url = "https://mirrors.kernel.org/pub/linux/utils/net/iproute2/iproute2-6.11.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  libmnl = {
    url = "https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  libnftnl = {
    url = "https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.2.8.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  iptables = {
    url = "https://www.netfilter.org/projects/iptables/files/iptables-1.8.10.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  nftables = {
    url = "https://www.netfilter.org/projects/nftables/files/nftables-1.1.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  curl = {
    url = "https://curl.se/download/curl-8.10.1.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  openssh = {
    url = "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  chrony = {
    url = "https://chrony-project.org/releases/chrony-4.6.1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  ca-certificates = {
    url = "https://curl.se/ca/cacert-2024-07-02.pem";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Init ---
  dbus = {
    url = "https://dbus.freedesktop.org/releases/dbus/dbus-1.14.10.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  util-linux = {
    url = "https://mirrors.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  kmod = {
    url = "https://mirrors.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  systemd = {
    url = "https://github.com/systemd/systemd-stable/archive/v256.9/systemd-256.9.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  dracut = {
    url = "https://github.com/dracut-ng/dracut-ng/archive/103/dracut-103.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Kubernetes ---
  kubernetes = {
    url = "https://github.com/kubernetes/kubernetes/archive/v1.31.4/kubernetes-1.31.4.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  crictl = {
    url = "https://github.com/kubernetes-sigs/cri-tools/archive/v1.31.1/cri-tools-1.31.1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  containerd = {
    url = "https://github.com/containerd/containerd/archive/v1.7.24/containerd-1.7.24.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  runc = {
    url = "https://github.com/opencontainers/runc/archive/v1.2.4/runc-1.2.4.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  cni-plugins = {
    url = "https://github.com/containernetworking/plugins/archive/v1.6.1/cni-plugins-1.6.1.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  helm = {
    url = "https://github.com/helm/helm/archive/v3.16.4/helm-3.16.4.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  ethtool = {
    url = "https://mirrors.kernel.org/pub/software/network/ethtool/ethtool-6.11.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  socat = {
    url = "http://www.dest-unreach.org/socat/download/socat-1.8.0.1.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  conntrack-tools = {
    url = "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.8.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  ipvsadm = {
    url = "https://mirrors.kernel.org/pub/linux/utils/kernel/ipvsadm/ipvsadm-1.31.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  nerdctl = {
    url = "https://github.com/containerd/nerdctl/archive/v1.7.7/nerdctl-1.7.7.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  libseccomp = {
    url = "https://github.com/seccomp/libseccomp/releases/download/v2.5.5/libseccomp-2.5.5.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Monitoring ---
  node-exporter = {
    url = "https://github.com/prometheus/node_exporter/archive/v1.8.2/node_exporter-1.8.2.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Image / Boot Tools ---
  butane = {
    url = "https://github.com/coreos/butane/archive/v0.21.0/butane-0.21.0.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  ignition = {
    url = "https://github.com/coreos/ignition/archive/v2.19.0/ignition-2.19.0.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  minisign = {
    url = "https://github.com/jedisct1/minisign/archive/0.11/minisign-0.11.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  sbsigntools = {
    url = "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/snapshot/sbsigntools-0.9.5.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Bootstrap ---
  mescc-tools = {
    url = "https://savannah.gnu.org/project/memberlist-gpgkeys.php?group=mescc-tools&download=1/mescc-tools-1.3.0.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  mes = {
    url = "mirror://gnu/mes/mes-0.27.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  tinycc = {
    url = "https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  gcc-464 = {
    url = "mirror://gnu/gcc/gcc-4.6.4/gcc-4.6.4.tar.bz2";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  gcc-750 = {
    url = "mirror://gnu/gcc/gcc-7.5.0/gcc-7.5.0.tar.xz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # --- Update ---
  update-tool = {
    url = "https://github.com/andyl/andyl-os/releases/download/v0.1.0/update-tool-0.1.0.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
}
