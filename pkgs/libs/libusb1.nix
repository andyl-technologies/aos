##! libusb1 — userspace USB device access library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.29";
in
  mkDerivation {
    pname = "libusb1";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libusb/libusb/releases/download/v${version}/libusb-${version}.tar.bz2"
      ];
      hash = "sha256-WXf8lQ+NE5XM6pvUjAaz+Aj9PCyWG0Swwubin8OnCoU=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libusb-${version}
        '';
      }
      {
        # --disable-udev: we don't link libudev, so hotplug notifications are
        # unavailable, but device enumeration via sysfs still works — which is
        # all GnuPG's scdaemon internal CCID driver needs to find a card reader.
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --disable-udev
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
      description = "Userspace library for accessing USB devices";
      homepage = "https://libusb.info/";
      license = "LGPL-2.1-or-later";
    };
  }
