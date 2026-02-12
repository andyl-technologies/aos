# ANDYL OS — Package set composition.
# Imports all package definitions and wires dependencies together.
# Bootstrap tools (gcc, coreutils, tar, etc.) are injected into every build.
# All other tools are built hermetically from source — no nixpkgs, no host tools.
{ lib }:

let
  fetchurl = lib.fetchurl;

  # Pre-built bootstrap tools provide gcc, coreutils, tar, make, etc.
  # in the Nix build sandbox where no system tools are available.
  bootstrapTools = import ../stdenv/bootstrap-tools.nix {
    system = lib.system;
  };

  # Dynamic linker path inside bootstrap-tools (architecture-dependent).
  dynamicLinker =
    if lib.system == "aarch64-linux" then
      "${bootstrapTools}/lib/ld-linux-aarch64.so.1"
    else
      "${bootstrapTools}/lib/ld-linux-x86-64.so.2";

  # Common compiler/linker flags needed because bootstrap tools' store
  # paths were nuked.  Every invocation of gcc/g++/cpp/ld must include these.
  defaultCFlags = "-B${bootstrapTools}/lib -isystem ${bootstrapTools}/include-glibc";
  defaultLdFlags = "-L${bootstrapTools}/lib -Wl,-dynamic-linker=${dynamicLinker} -Wl,-rpath,${bootstrapTools}/lib";

  # CC wrapper — shell scripts that prepend the required flags to every
  # gcc/g++/cpp/ld invocation.  This mirrors the nixpkgs cc-wrapper
  # approach: even when a Makefile calls bare `gcc`, the wrapper ensures
  # headers and libraries are found.
  ccWrapper = builtins.derivation {
    name = "cc-wrapper";
    system = lib.system;
    builder = "/bin/sh";
    PATH = "${bootstrapTools}/bin";
    # Pass values as env vars so the builder script can reference them
    REAL_GCC = "${bootstrapTools}/bin/gcc";
    REAL_GPP = "${bootstrapTools}/bin/g++";
    REAL_CPP = "${bootstrapTools}/bin/cpp";
    REAL_LD = "${bootstrapTools}/bin/ld";
    BT_LIB = "${bootstrapTools}/lib";
    BT_INC = "${bootstrapTools}/include-glibc";
    CRT1 = "${bootstrapTools}/lib/crt1.o";
    DYN_LINK = dynamicLinker;
    args = [
      "-c"
      ''
              set -e
              mkdir -p $out/bin $out/lib

              # Create Scrt1.o (PIE variant) — symlink to crt1.o since the
              # bootstrap glibc doesn't ship Scrt1.o separately.
              ln -s $CRT1 $out/lib/Scrt1.o
              ln -s $CRT1 $out/lib/rcrt1.o

              # Discover C++ include paths for -nostdinc++ re-addition.
              # Bootstrap GCC's built-in system header dir was nuked, so
              # #include_next <stdlib.h> from cstdlib fails.  Fix: use
              # -nostdinc++ to remove the broken built-in C++ search dirs,
              # then re-add them via -isystem WITH include-glibc placed AFTER
              # the C++ dirs.  This lets #include_next find stdlib.h.
              BT_ROOT=$(dirname $BT_LIB)
              CXX_VER=$(ls "$BT_ROOT/include/c++")
              BT_CXX="$BT_ROOT/include/c++/$CXX_VER"
              BT_CXX_ARCH=$(ls -d "$BT_CXX"/*-linux-gnu 2>/dev/null | head -1)
              BT_CXX_BACKWARD="$BT_CXX/backward"

              # Discover GCC library directory (contains libstdc++.so, libgcc_s.so)
              BT_GCC_LIB=$(ls -d "$BT_LIB/gcc"/*/*/ 2>/dev/null | head -1)

              # gcc wrapper (C only — no C++ path issues)
              # $NIX_LDFLAGS is set by mkDerivation with -Wl,-rpath for all deps
              cat > $out/bin/gcc << GCCEOF
        #!/bin/sh
        exec $REAL_GCC -B$out/lib -B$BT_LIB -isystem $BT_INC -L$BT_LIB -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYN_LINK -Wl,-rpath,$BT_LIB -Wl,-rpath,$BT_GCC_LIB \$NIX_LDFLAGS "\$@"
        GCCEOF

              cp $out/bin/gcc $out/bin/cc

              # g++ wrapper — uses -nostdinc++ then re-adds C++ headers before
              # glibc headers so #include_next from cstdlib finds stdlib.h
              cat > $out/bin/g++ << GPPEOF
        #!/bin/sh
        exec $REAL_GPP -nostdinc++ -isystem $BT_CXX -isystem $BT_CXX_ARCH -isystem $BT_CXX_BACKWARD -isystem $BT_INC -B$out/lib -B$BT_LIB -L$BT_LIB -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYN_LINK -Wl,-rpath,$BT_LIB -Wl,-rpath,$BT_GCC_LIB \$NIX_LDFLAGS "\$@"
        GPPEOF

              cp $out/bin/g++ $out/bin/c++

              # cpp wrapper (preprocessor only)
              cat > $out/bin/cpp << CPPEOF
        #!/bin/sh
        exec $REAL_CPP -isystem $BT_INC "\$@"
        CPPEOF

              # ld wrapper — note: ld uses -rpath (not -Wl,-rpath), so we don't
              # pass $NIX_LDFLAGS here (which uses gcc format).  Builds go through
              # gcc/g++ which handle it.
              cat > $out/bin/ld << LDEOF
        #!/bin/sh
        exec $REAL_LD -L$BT_LIB -L$BT_GCC_LIB -dynamic-linker=$DYN_LINK -rpath $BT_LIB -rpath $BT_GCC_LIB "\$@"
        LDEOF

              chmod +x $out/bin/*
      ''
    ];
  };

  # Wrap lib.mkDerivation to automatically include bootstrap tools in PATH
  # and set the correct compiler/linker flags so that compiled programs
  # can find the dynamic linker and shared libraries.
  mkDerivation =
    args:
    lib.mkDerivation (
      args
      // {
        # ccWrapper goes first in PATH so its wrappers shadow bootstrap gcc
        buildDeps = [
          ccWrapper
          bootstrapTools
        ]
        ++ (args.buildDeps or [ ]);

        # Explicit CC/CXX/CPP point to wrappers so configure scripts use them
        CC = "${ccWrapper}/bin/gcc";
        CXX = "${ccWrapper}/bin/g++";
        CPP = "${ccWrapper}/bin/cpp";
        AR = "${bootstrapTools}/bin/ar";
        AS = "${bootstrapTools}/bin/as";
        LD = "${ccWrapper}/bin/ld";
        NM = "${bootstrapTools}/bin/nm";
        RANLIB = "${bootstrapTools}/bin/ranlib";
        STRIP = "${bootstrapTools}/bin/strip";
        CONFIG_SHELL = "${bootstrapTools}/bin/bash";

        # Also set CFLAGS/LDFLAGS for build systems that use them directly
        CPPFLAGS = "-isystem ${bootstrapTools}/include-glibc ${args.CPPFLAGS or ""}";
        CFLAGS = "${defaultCFlags} ${args.CFLAGS or ""}";
        LDFLAGS = "${defaultLdFlags} ${args.LDFLAGS or ""}";
      }
    );

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage =
    path: overrides:
    let
      fn = import path;
      auto = builtins.intersectAttrs (builtins.functionArgs fn) (
        self
        // {
          inherit mkDerivation fetchurl;
        }
      );
    in
    fn (auto // overrides);

  # Shared Kubernetes source (single tarball for kubelet, kubeadm, kubectl)
  kubeSource = import ./kubernetes/source.nix { inherit fetchurl; };

  self = {
    # --- Plumbing ---
    inherit mkDerivation fetchurl lib;

    # --- Toolchain ---
    gcc = callPackage ./toolchain/gcc.nix { };
    binutils = callPackage ./toolchain/binutils.nix { };
    linux-headers = callPackage ./toolchain/linux-headers.nix { };

    # --- Core ---
    make = callPackage ./core/make.nix { };
    coreutils = callPackage ./core/coreutils.nix { };
    bash = callPackage ./core/bash.nix { };
    findutils = callPackage ./core/findutils.nix { };
    gawk = callPackage ./core/gawk.nix { };
    grep = callPackage ./core/grep.nix { };
    sed = callPackage ./core/sed.nix { };
    tar = callPackage ./core/tar.nix { };
    gzip = callPackage ./core/gzip.nix { };
    xz = callPackage ./core/xz.nix { };
    diffutils = callPackage ./core/diffutils.nix { };
    patch = callPackage ./core/patch.nix { };
    pkg-config = callPackage ./core/pkg-config.nix { };
    perl = callPackage ./core/perl.nix { };
    bison = callPackage ./core/bison.nix { };
    texinfo = callPackage ./core/texinfo.nix { };
    dosfstools = callPackage ./core/dosfstools.nix { };
    e2fsprogs = callPackage ./core/e2fsprogs.nix { };
    jq = callPackage ./core/jq.nix { };
    expat = callPackage ./core/expat.nix { };
    m4 = callPackage ./core/m4.nix { };
    flex = callPackage ./core/flex.nix { };
    gperf = callPackage ./core/gperf.nix { };
    elfutils = callPackage ./core/elfutils.nix { };
    ninja = callPackage ./core/ninja.nix { };
    python3 = callPackage ./core/python3.nix { };
    meson = callPackage ./core/meson.nix { };
    rsync = callPackage ./core/rsync.nix { };
    pcre2 = callPackage ./core/pcre2.nix { };
    bc = callPackage ./core/bc.nix { };

    # --- Compression ---
    zlib = callPackage ./compression/zlib.nix { };
    zstd = callPackage ./compression/zstd.nix { };
    lz4 = callPackage ./compression/lz4.nix { };

    # --- TLS ---
    openssl = callPackage ./tls/openssl.nix { };

    # --- Init ---
    dbus = callPackage ./init/dbus.nix { };
    util-linux = callPackage ./init/util-linux.nix { };
    kmod = callPackage ./init/kmod.nix { };
    systemd = callPackage ./init/systemd.nix { };

    # --- Kernel ---
    linux = callPackage ./kernel/linux.nix { };
    firmware = callPackage ./kernel/firmware.nix { };

    # --- Security ---
    libcap = callPackage ./security/libcap.nix { };
    libxcrypt = callPackage ./security/libxcrypt.nix { };
    audit = callPackage ./security/audit.nix { };
    libsepol = callPackage ./security/libsepol.nix { };
    libselinux = callPackage ./security/libselinux.nix { };
    libsemanage = callPackage ./security/libsemanage.nix { };
    policycoreutils = callPackage ./security/policycoreutils.nix { };
    setools = callPackage ./security/setools.nix { };
    refpolicy = callPackage ./security/refpolicy.nix { };
    container-selinux = callPackage ./security/container-selinux.nix { };

    # --- Storage ---
    zfs = callPackage ./storage/zfs.nix { };

    # --- Networking ---
    libmnl = callPackage ./networking/libmnl.nix { };
    libnftnl = callPackage ./networking/libnftnl.nix { };
    iproute2 = callPackage ./networking/iproute2.nix { };
    iptables = callPackage ./networking/iptables.nix { };
    nftables = callPackage ./networking/nftables.nix { };
    curl = callPackage ./networking/curl.nix { };
    openssh = callPackage ./networking/openssh.nix { };
    chrony = callPackage ./networking/chrony.nix { };
    ca-certificates = callPackage ./networking/ca-certificates.nix { };

    # --- Containers ---
    libseccomp = callPackage ./containers/libseccomp.nix { };
    runc = callPackage ./containers/runc.nix { };
    containerd = callPackage ./containers/containerd.nix { };

    # --- Kubernetes ---
    kubelet = callPackage ./kubernetes/kubelet.nix { inherit kubeSource; };
    kubeadm = callPackage ./kubernetes/kubeadm.nix { inherit kubeSource; };
    kubectl = callPackage ./kubernetes/kubectl.nix { inherit kubeSource; };
    crictl = callPackage ./kubernetes/crictl.nix { };
    cni-plugins = callPackage ./kubernetes/cni-plugins.nix { };
    helm = callPackage ./kubernetes/helm.nix { };
    nerdctl = callPackage ./kubernetes/nerdctl.nix { };
    ethtool = callPackage ./kubernetes/ethtool.nix { };
    socat = callPackage ./kubernetes/socat.nix { };
    conntrack-tools = callPackage ./kubernetes/conntrack-tools.nix { };
    ipvsadm = callPackage ./kubernetes/ipvsadm.nix { };

    # --- Monitoring ---
    node-exporter = callPackage ./monitoring/node-exporter.nix { };

    # --- Boot ---
    dracut = callPackage ./boot/dracut.nix { };
    ignition = callPackage ./boot/ignition.nix { };
    butane = callPackage ./boot/butane.nix { };

    # --- Tools ---
    minisign = callPackage ./tools/minisign.nix { };
    sbsigntools = callPackage ./tools/sbsigntools.nix { };
  };

in
self
