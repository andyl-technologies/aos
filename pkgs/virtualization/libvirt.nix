##! libvirt — Virtualization management toolkit and system daemons
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  gettext,
  perl,
  python3,
  docutils,
  bash,
  bash-completion,
  coreutils,
  util-linux,
  rpcsvc-proto,
  libxml2,
  libxslt,
  docbook-xml,
  docbook-xsl,
  acl,
  attr,
  audit,
  bridge-utils,
  curl,
  cyrus-sasl,
  dbus,
  dnsmasq,
  fuse3,
  glib,
  gnutls,
  iproute2,
  iptables,
  nftables,
  libapparmor,
  libcap-ng,
  libgcrypt,
  libnl,
  libpcap,
  libpciaccess,
  libselinux,
  libssh2,
  libtasn1,
  libtirpc,
  lvm2,
  numactl,
  numad,
  parted,
  passt,
  pm-utils,
  polkit,
  qemu,
  readline,
  swtpm,
  systemd,
  zfs,
  json-c,
  buildPackages,
}: let
  version = "12.7.0";
  runtimeTools = [
    bash
    bridge-utils
    coreutils
    dbus
    dnsmasq
    iproute2
    iptables
    nftables
    numactl
    numad
    parted
    passt
    pm-utils
    qemu
    swtpm
    systemd
    util-linux
    zfs
  ];
  runtimePath = builtins.concatStringsSep ":" (map (package: "${package}/bin") runtimeTools);
in
  mkDerivation {
    pname = "libvirt";
    inherit version;

    src = fetchurl {
      urls = ["https://download.libvirt.org/libvirt-${version}.tar.xz"];
      hash = "sha256-fsGgTn5PQGk1PU2qwRe76Gkof1sgJpXeYf4bB577bLY=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      gettext
      perl
      python3
      docutils
      bash
      bash-completion
      glib.dev
      util-linux
      rpcsvc-proto
      libxml2
      libxslt
      docbook-xml
      docbook-xsl
    ];
    runtimeDeps = [
      acl
      attr
      audit
      bash
      bash-completion
      bridge-utils
      curl
      cyrus-sasl
      dbus
      dnsmasq
      fuse3
      glib
      gnutls
      iproute2
      iptables
      nftables
      libapparmor
      libcap-ng
      libgcrypt
      libnl
      libpcap
      libpciaccess
      libselinux
      libssh2
      libtasn1
      libtirpc
      libxml2
      libxslt
      lvm2
      numactl
      numad
      parted
      passt
      pm-utils
      polkit
      qemu
      readline
      swtpm
      systemd
      util-linux
      zfs
      json-c
    ];
    propagatedDeps = [libxml2];

    passthru.systemdUnitInventory = {
      system = [
        "lib/systemd/system/libvirtd.service"
        "lib/systemd/system/libvirtd.socket"
        "lib/systemd/system/libvirtd-ro.socket"
        "lib/systemd/system/libvirtd-admin.socket"
        "lib/systemd/system/virtlockd.service"
        "lib/systemd/system/virtlockd.socket"
        "lib/systemd/system/virtlockd-admin.socket"
        "lib/systemd/system/virtlogd.service"
        "lib/systemd/system/virtlogd.socket"
        "lib/systemd/system/virtlogd-admin.socket"
      ];
      user = [];
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libvirt-${version}
          patch -p1 < ${./libvirt-install-prefix.patch}

          # System mode selects daemon behavior and runtime paths, but package
          # files still belong under the immutable Meson prefix.
          sed -i \
            "/# nix: don't prefix the localstatedir/i\\prefix = get_option('prefix')\\nlibdir = prefix / get_option('libdir')\\n" \
            meson.build

          find . -type f -name '*.py' -exec \
            sed -i '1s|^#!.*python.*$|#!${python3}/bin/python3|' {} +
          grep -rl '^#!/usr/bin/env python3' . | while read file; do
            sed -i '1s|.*|#!${python3}/bin/python3|' "$file"
          done
          find . -type f -name '*.pl' -exec \
            sed -i '1s|^#!.*perl.*$|#!${perl}/bin/perl|' {} +
          find . -type f \( -name '*.sh' -o -name '*.in' \) -exec \
            sed -i \
              -e '1s|^#! */bin/sh|#!${bash}/bin/bash|' \
              -e '1s|^#! */bin/bash|#!${bash}/bin/bash|' \
              -e '1s|^#! */usr/bin/env bash|#!${bash}/bin/bash|' \
              {} +

          sed -i \
            's|/usr/bin/sh|${bash}/bin/bash|g' \
            src/secret/virt-secret-init-encryption.service.in
          sed -i \
            's|"/usr/bin/pkttyagent"|"${polkit}/bin/pkttyagent"|' \
            src/util/virpolkit.h
          sed -i \
            's|#define PARTED "parted"|#define PARTED "${parted}/bin/parted"|' \
            src/storage/storage_backend_disk.c \
            src/storage/storage_util.c
          sed -i \
            -e 's|#define ZFS "zfs"|#define ZFS "${zfs}/bin/zfs"|' \
            -e 's|#define ZPOOL "zpool"|#define ZPOOL "${zfs}/bin/zpool"|' \
            src/storage/storage_backend_zfs.c

          sed -i \
            -e "s|conf.set_quoted('QEMU_BRIDGE_HELPER',.*|conf.set_quoted('QEMU_BRIDGE_HELPER', '/run/wrappers/bin/qemu-bridge-helper')|" \
            -e "s|conf.set_quoted('QEMU_PR_HELPER',.*|conf.set_quoted('QEMU_PR_HELPER', '/run/libvirt/helpers/qemu-pr-helper')|" \
            meson.build

        '';
      }
      {
        name = "configure";
        script = ''
          export PATH="${runtimePath}:$PATH"
          export PKG_CONFIG_PATH="${bash-completion}/share/pkgconfig:$PKG_CONFIG_PATH"
          export XML_CATALOG_FILES="${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson setup build \
              $mesonFlags \
              --prefix="$out" \
              --sysconfdir=/etc \
              --localstatedir=/var \
              --buildtype=release \
              -Dinstall_prefix="$out" \
              -Dsystem=true \
              -Drunstatedir=/run \
              -Dinit_script=systemd \
              -Dunitdir="$out/lib/systemd/system" \
              -Dsysusersdir="$out/lib/sysusers.d" \
              -Dsshconfdir=/etc/ssh/ssh_config.d \
              -Dqemu_datadir=${qemu}/share/qemu \
              -Dqemu_user=libvirt-qemu \
              -Dqemu_group=libvirt-qemu \
              -Dch_user=libvirt-qemu \
              -Dch_group=libvirt-qemu \
              -Dapparmor=enabled \
              -Dapparmor_profiles=enabled \
              -Dattr=enabled \
              -Daudit=enabled \
              -Dbash_completion=enabled \
              -Dblkid=enabled \
              -Dcapng=enabled \
              -Dcurl=enabled \
              -Ddocs=enabled \
              -Dexpensive_tests=enabled \
              -Dfirewalld=enabled \
              -Dfirewalld_zone=enabled \
              -Dfuse=enabled \
              -Dhost_validate=enabled \
              -Djson_c=enabled \
              -Dlibnl=enabled \
              -Dlibpcap=enabled \
              -Dlibssh2=enabled \
              -Dnls=enabled \
              -Dnumactl=enabled \
              -Dnumad=enabled \
              -Dpciaccess=enabled \
              -Dpolkit=enabled \
              -Dreadline=enabled \
              -Dsasl=enabled \
              -Dselinux=enabled \
              -Dudev=enabled \
              -Dlibvirtd=enabled \
              -Dlogin_shell=enabled \
              -Dnss=enabled \
              -Dpm_utils=enabled \
              -Dssh_proxy=enabled \
              -Dsysctl_config=enabled \
              -Dtls_priority=enabled \
              -Dtests=enabled \
              -Ddriver_ch=enabled \
              -Ddriver_esx=enabled \
              -Ddriver_interface=enabled \
              -Ddriver_libvirtd=enabled \
              -Ddriver_lxc=enabled \
              -Ddriver_network=enabled \
              -Ddriver_openvz=enabled \
              -Ddriver_qemu=enabled \
              -Ddriver_remote=enabled \
              -Ddriver_secrets=enabled \
              -Ddriver_test=enabled \
              -Ddriver_vbox=enabled \
              -Ddriver_vmware=enabled \
              -Dstorage_dir=enabled \
              -Dstorage_disk=enabled \
              -Dstorage_fs=enabled \
              -Dstorage_lvm=enabled \
              -Dstorage_mpath=enabled \
              -Dstorage_scsi=enabled \
              -Dstorage_vstorage=enabled \
              -Dstorage_zfs=enabled \
              -Dsecdriver_apparmor=enabled \
              -Dsecdriver_selinux=enabled \
              -Dglusterfs=disabled \
              -Dlibiscsi=disabled \
              -Dlibssh=disabled \
              -Dnetcf=disabled \
              -Dopenwsman=disabled \
              -Dsanlock=disabled \
              -Dwireshark_dissector=disabled \
              -Ddriver_bhyve=disabled \
              -Ddriver_hyperv=disabled \
              -Ddriver_libxl=disabled \
              -Ddriver_vz=disabled \
              -Dstorage_gluster=disabled \
              -Dstorage_iscsi=disabled \
              -Dstorage_iscsi_direct=disabled \
              -Dstorage_rbd=disabled
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="${runtimePath}:$PATH"
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          export PATH="${runtimePath}:$PATH"
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages

          # AOS uses its packaged QEMU data and feature set, while these four
          # tests compare generated XML against upstream FHS/QEMU fixtures.
          # The command fixture hard-codes /usr/bin:/bin, and the dual-stack
          # socket case depends on sandbox IPv6 routing.
          # Run every other upstream test, including expensive tests.
          ${bash}/bin/bash <<'EOF'
          mapfile -t tests < <(meson test -C build --no-rebuild --list)
          selected=()
          for test in "''${tests[@]}"; do
            name="''${test#* - }"
            case "$name" in
              *:qemufirmwaretest|*:qemuvhostusertest|*:domaincapstest|*:qemuxmlconftest|*:commandtest|*:virnetsockettest)
                ;;
              *)
                selected+=("$name")
                ;;
            esac
          done
          meson test -C build \
            --no-rebuild \
            --print-errorlogs \
            --timeout-multiplier 4 \
            "''${selected[@]}"
          EOF
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="${runtimePath}:$PATH"
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install

          sed -i \
            's|xmllint|${libxml2}/bin/xmllint|' \
            "$out/bin/virt-xml-validate"
          find "$out" -type f -perm /0111 -exec \
            sed -i \
              -e '1s|^#! */bin/sh|#!${bash}/bin/bash|' \
              -e '1s|^#! */bin/bash|#!${bash}/bin/bash|' \
              -e '1s|^#! */usr/bin/env bash|#!${bash}/bin/bash|' \
              {} +

          chmod u-s,g-s "$out/bin/virt-login-shell" 2>/dev/null || true
          "$out/bin/virsh" --version
          "$out/bin/virt-host-validate" --version
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "libvirt";
        library = self;
        libs = ["-lvirt"];
        testSource = ''
          #include <libvirt/libvirt.h>

          int main(void) {
              return virInitialize() < 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-libvirt";
        tool = self;
        command = "virsh --version && virt-xml-validate --help";
      };
    };

    meta = {
      description = "Toolkit for managing platform virtualization";
      homepage = "https://libvirt.org/";
      license = "LGPL-2.1-or-later";
      mainProgram = "virsh";
    };
  }
