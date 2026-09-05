##! libpciaccess — Generic PCI access library
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  hwdata,
  zlib,
}: let
  version = "0.19";
in
  mkDerivation {
    pname = "libpciaccess";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.x.org/releases/individual/lib/libpciaccess-${version}.tar.xz"
      ];
      hash = "sha256-PFWqhsguVKTjEJeG8EY1MNU7NrbRz9FGFkVPmF3SqkM=";
    };

    buildDeps = [meson ninja pkg-config];
    runtimeDeps = [hwdata zlib];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpciaccess-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --libdir=lib \
            -Dzlib=enabled \
            -Dpci-ids="${hwdata}/share/hwdata"
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpciaccess";
        library = self;
        libs = ["-lpciaccess"];
        testSource = ''
          #include <errno.h>
          #include <pciaccess.h>

          int main(void) {
              int status = pci_system_init();
              if (status == 0) pci_system_cleanup();
              return status == 0 || status == EACCES || status == ENOENT ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Generic PCI access library";
      homepage = "https://gitlab.freedesktop.org/xorg/lib/libpciaccess";
      license = "MIT AND ISC";
    };
  }
