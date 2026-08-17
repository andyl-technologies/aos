##! device-mapper — Device-mapper userspace library and tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libaio,
  util-linux,
}: let
  version = "2.03.28";
in
  mkDerivation {
    pname = "device-mapper";
    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceware.org/ftp/lvm2/LVM2.${version}.tgz"
        "https://mirrors.kernel.org/sourceware/lvm2/LVM2.${version}.tgz"
      ];
      hash = "sha256-uCK6/2ti3zY4LHF866mKJojrsxvyt2jz/6K21eJVckI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libaio
      util-linux
    ];
    propagatedDeps = [
      libaio
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd LVM2.${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-pkgconfig \
            --enable-cmdlib \
            --enable-udev_rules \
            --enable-dmeventd=none \
            --with-thin=none \
            --with-cache=none \
            --disable-selinux \
            --disable-readline \
            --disable-editline
        '';
      }
      {
        name = "build";
        script = ''
          make device-mapper -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install_device-mapper

          # systemd can observe the initial dm add event before activation and
          # persist SYSTEMD_READY=0. Since libdevmapper cannot depend on
          # systemd's libudev in the bootstrap graph, clear that conservative
          # state only after sysfs confirms that the mapping is unsuspended.
          cat > $out/lib/udev/rules.d/99-z-aos-dm-ready.rules <<'EOF'
          SUBSYSTEM=="block", KERNEL=="dm-*", TEST=="dm/name", ATTR{dm/suspended}=="0", ENV{DM_NAME}="$attr{dm/name}", ENV{SYSTEMD_READY}="1", TAG+="systemd"
          EOF
        '';
      }
    ];

    meta = {
      description = "Device-mapper userspace library and tools (libdevmapper, dmsetup)";
      homepage = "https://sourceware.org/lvm2/";
      license = "LGPL-2.1-only";
    };
  }
