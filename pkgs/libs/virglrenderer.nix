##! VirGL and Venus host graphics renderer
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  check,
  libdrm,
  libepoxy,
  libglvnd,
  libva,
  libx11,
  mesa,
  vulkan-loader,
}: let
  version = "1.3.0";
  meson = "${buildPackages.python3}/bin/python3 -m mesonbuild.mesonmain";
in
  mkDerivation {
    pname = "virglrenderer";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/virgl/virglrenderer/-/archive/${version}/virglrenderer-${version}.tar.gz"];
      hash = "sha256-BlvFbonm9jH5YQHNYuugdI5I64iLQ07chuidBTledvM=";
    };

    buildDeps = [
      buildPackages.meson
      buildPackages.ninja
      buildPackages.pkg-config
      buildPackages.python3
      buildPackages.python3-pyyaml
      check
    ];
    runtimeDeps = [libdrm libepoxy libglvnd libva libx11 mesa vulkan-loader];
    PYTHONPATH = "${buildPackages.meson}/lib/python3/site-packages:${buildPackages.python3-pyyaml}/lib/python3.14/site-packages";

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd virglrenderer-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            ${meson} setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release --wrap-mode=nodownload \
              -Dplatforms=egl,glx -Dvenus=true -Dvulkan-dload=false \
              -Dvideo=true -Dtests=true -Dunstable-apis=true
          '';
        }
        {
          name = "build";
          script = ''
            ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            # Check and EGL are loaded dynamically by upstream's test runner.
            # Pin the source-built Mesa vendor and software renderer so the
            # suite exercises EGL without requiring a display or DRM device.
            export LD_LIBRARY_PATH="${check}/lib:${libglvnd}/lib:${mesa}/lib"
            export __EGL_VENDOR_LIBRARY_FILENAMES=${mesa}/share/glvnd/egl_vendor.d/50_mesa.json
            export LIBGL_DRIVERS_PATH=${mesa}/lib/dri
            export LIBGL_ALWAYS_SOFTWARE=1
            export VRENDTEST_USE_EGL_SURFACELESS=1
            ${meson} test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            ninja -C build install
            mkdir -p "$out/share/licenses/virglrenderer"
            cp COPYING "$out/share/licenses/virglrenderer/"
          '';
        }
      ];

    meta = {
      description = "VirGL and Venus host graphics renderer with EGL, GLX and video support";
      homepage = "https://gitlab.freedesktop.org/virgl/virglrenderer";
      license = "MIT";
    };
  }
