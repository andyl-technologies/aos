##! linux-pam — Pluggable Authentication Modules
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  flex,
  bison,
  gettext,
  python3,
  libxcrypt,
  audit,
}: let
  version = "1.7.1";
in
  mkDerivation {
    pname = "linux-pam";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/linux-pam/linux-pam/releases/download/v${version}/Linux-PAM-${version}.tar.xz"
        "https://github.com/linux-pam/linux-pam/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-IdvOxuAd1XjxR4nqyQJKGJQebycCoFz5GyjCMu6yarA=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      flex
      bison
      gettext
      python3
    ];
    runtimeDeps = [
      libxcrypt
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd Linux-PAM-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Meson needs to find its own Python modules (ninja invokes
          # python3 -m mesonbuild.mesonmain directly).
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --buildtype=release \
            --libdir=lib \
            -Ddefault_library=both \
            -Ddocs=disabled \
            -Dexamples=false \
            -Dxtests=false \
            -Dnis=disabled \
            -Dselinux=disabled \
            -Delogind=disabled \
            -Dlogind=disabled \
            -Dopenssl=disabled \
            -Dpam_userdb=disabled \
            -Dpam_unix=enabled \
            -Daudit=enabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    meta = {
      description = "Pluggable Authentication Modules for Linux";
      homepage = "https://github.com/linux-pam/linux-pam";
      license = "BSD-3-Clause";
    };
  }
