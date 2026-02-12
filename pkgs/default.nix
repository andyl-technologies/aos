# ANDYL OS — Package set composition.
# Imports all package definitions and wires dependencies together.
# No nixpkgs dependency — everything is built from our own mkDerivation.
{ lib }:

let
  fetchurl = lib.fetchurl;
  mkDerivation = lib.mkDerivation;

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage = path: overrides:
    let
      fn = import path;
      auto = builtins.intersectAttrs
        (builtins.functionArgs fn)
        (self // {
          inherit mkDerivation fetchurl;
        });
    in fn (auto // overrides);

  # Shared Kubernetes source (single tarball for kubelet, kubeadm, kubectl)
  kubeSource = import ./kubernetes/source.nix { inherit fetchurl; };

  self = {
    # --- Plumbing ---
    inherit mkDerivation fetchurl lib;

    # --- Toolchain ---
    gcc          = callPackage ./toolchain/gcc.nix {};
    binutils     = callPackage ./toolchain/binutils.nix {};
    linux-headers = callPackage ./toolchain/linux-headers.nix {};

    # --- Core ---
    make         = callPackage ./core/make.nix {};
    coreutils    = callPackage ./core/coreutils.nix {};
    bash         = callPackage ./core/bash.nix {};
    findutils    = callPackage ./core/findutils.nix {};
    gawk         = callPackage ./core/gawk.nix {};
    grep         = callPackage ./core/grep.nix {};
    sed          = callPackage ./core/sed.nix {};
    tar          = callPackage ./core/tar.nix {};
    gzip         = callPackage ./core/gzip.nix {};
    xz           = callPackage ./core/xz.nix {};
    diffutils    = callPackage ./core/diffutils.nix {};
    patch        = callPackage ./core/patch.nix {};
    pkg-config   = callPackage ./core/pkg-config.nix {};
    perl         = callPackage ./core/perl.nix {};
    bison        = callPackage ./core/bison.nix {};
    texinfo      = callPackage ./core/texinfo.nix {};
    dosfstools   = callPackage ./core/dosfstools.nix {};
    e2fsprogs    = callPackage ./core/e2fsprogs.nix {};
    jq           = callPackage ./core/jq.nix {};

    # --- Compression ---
    zlib         = callPackage ./compression/zlib.nix {};
    zstd         = callPackage ./compression/zstd.nix {};
    lz4          = callPackage ./compression/lz4.nix {};

    # --- TLS ---
    openssl      = callPackage ./tls/openssl.nix {};

    # --- Init ---
    dbus         = callPackage ./init/dbus.nix {};
    util-linux   = callPackage ./init/util-linux.nix {};
    kmod         = callPackage ./init/kmod.nix {};
    systemd      = callPackage ./init/systemd.nix {};

    # --- Kernel ---
    linux        = callPackage ./kernel/linux.nix {};
    firmware     = callPackage ./kernel/firmware.nix {};

    # --- Security ---
    audit        = callPackage ./security/audit.nix {};
    libsepol     = callPackage ./security/libsepol.nix {};
    libselinux   = callPackage ./security/libselinux.nix {};
    libsemanage  = callPackage ./security/libsemanage.nix {};
    policycoreutils = callPackage ./security/policycoreutils.nix {};
    setools      = callPackage ./security/setools.nix {};
    refpolicy    = callPackage ./security/refpolicy.nix {};
    container-selinux = callPackage ./security/container-selinux.nix {};

    # --- Storage ---
    zfs          = callPackage ./storage/zfs.nix {};

    # --- Networking ---
    libmnl       = callPackage ./networking/libmnl.nix {};
    libnftnl     = callPackage ./networking/libnftnl.nix {};
    iproute2     = callPackage ./networking/iproute2.nix {};
    iptables     = callPackage ./networking/iptables.nix {};
    nftables     = callPackage ./networking/nftables.nix {};
    curl         = callPackage ./networking/curl.nix {};
    openssh      = callPackage ./networking/openssh.nix {};
    chrony       = callPackage ./networking/chrony.nix {};
    ca-certificates = callPackage ./networking/ca-certificates.nix {};

    # --- Containers ---
    libseccomp   = callPackage ./containers/libseccomp.nix {};
    runc         = callPackage ./containers/runc.nix {};
    containerd   = callPackage ./containers/containerd.nix {};

    # --- Kubernetes ---
    kubelet      = callPackage ./kubernetes/kubelet.nix { inherit kubeSource; };
    kubeadm      = callPackage ./kubernetes/kubeadm.nix { inherit kubeSource; };
    kubectl      = callPackage ./kubernetes/kubectl.nix { inherit kubeSource; };
    crictl       = callPackage ./kubernetes/crictl.nix {};
    cni-plugins  = callPackage ./kubernetes/cni-plugins.nix {};
    helm         = callPackage ./kubernetes/helm.nix {};
    nerdctl      = callPackage ./kubernetes/nerdctl.nix {};
    ethtool      = callPackage ./kubernetes/ethtool.nix {};
    socat        = callPackage ./kubernetes/socat.nix {};
    conntrack-tools = callPackage ./kubernetes/conntrack-tools.nix {};
    ipvsadm      = callPackage ./kubernetes/ipvsadm.nix {};

    # --- Monitoring ---
    node-exporter = callPackage ./monitoring/node-exporter.nix {};

    # --- Boot ---
    dracut       = callPackage ./boot/dracut.nix {};
    ignition     = callPackage ./boot/ignition.nix {};
    butane       = callPackage ./boot/butane.nix {};

    # --- Tools ---
    minisign     = callPackage ./tools/minisign.nix {};
    sbsigntools  = callPackage ./tools/sbsigntools.nix {};
};

in self
