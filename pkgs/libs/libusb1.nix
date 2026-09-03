##! libusb1 — userspace USB device access library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "libusb-1";
    family = "libusb";
    member = "libusb1";
    stream = "1";
    owner = "pkgs/libs/libusb1.nix";
    version = "1.0.29";
    upstreamId = "v1.0.29";
    repository = "libusb/libusb";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "libusb"
        "libusb"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "libusb-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.bz2";}
          ];
        }
      ];
      hash = "sha256-WXf8lQ+NE5XM6pvUjAaz+Aj9PCyWG0Swwubin8OnCoU=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libusb1";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libusb-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
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
