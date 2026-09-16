##! D-Bus — Message bus system
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  expat,
  libselinux,
  audit,
  libcap-ng,
  systemd,
  stdenv,
}: let
  version = "1.16.2";
in
  mkDerivation {
    pname = "dbus";
    inherit version;

    src = fetchurl {
      urls = [
        "https://dbus.freedesktop.org/releases/dbus/dbus-${version}.tar.xz"
      ];
      hash = "sha256-C6KhpLFq/nvOssB+nOmajCw1COXewpDbtkM4S9a+t+I=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      python3
    ];
    runtimeDeps =
      [expat]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [
          libselinux
          audit
          libcap-ng
          # libsystemd for sd_notify + unit file installation. Systemd
          # no longer depends on dbus at the pkg level (sd-bus replaces
          # libdbus), so this direction is cycle-free.
          systemd
        ]
      );
    propagatedDeps = [];

    # Pure stage-2 inventory for consumers that opt into
    # `systemd.packages = [ pkgs.dbus ]`.
    passthru.systemdUnitInventory = {
      system = [];
      user = [
        "lib/systemd/user/dbus.service"
        "lib/systemd/user/dbus.socket"
        "lib/systemd/user/sockets.target.wants/dbus.socket"
      ];
    };

    # dbus-daemon crash-loops on activation under -fstrict-flex-arrays=3
    # (its trailing-array message structs trip _FORTIFY_SOURCE at runtime).
    # Step down to level 1; fortify3 and the rest stay on.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dbus-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          for script in \
            meson_post_install.py \
            test/data/copy_data_for_tests.py \
            tools/build-timestamp.py; do
            sed -i "1s|^#!.*|#!${python3}/bin/python3|" "$script"
          done
        '';
      }
      {
        name = "configure";
        # Enable systemd so dbus installs its user service/socket units and
        # sockets.target.wants link for systemd.packages consumers.
        # --sysconfdir=/etc so
        # baked-in config lookups go to /etc/dbus-1 on the running system,
        # not a read-only store path.
        script = ''
          export PYTHONPATH="${meson}/lib/python3/site-packages"
          meson setup build \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            -Dintrusive_tests=false \
            -Dmodular_tests=disabled \
            -Dinstalled_tests=false \
            -Ddoxygen_docs=disabled \
            -Dducktype_docs=disabled \
            -Dqt_help=disabled \
            -Dxml_docs=disabled \
            -Dsystemd_system_unitdir="$out/lib/systemd/system" \
            -Dsystemd_user_unitdir="$out/lib/systemd/user" \
            -Dsystemd=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Duser_session=true \
            -Dapparmor=disabled \
            -Dselinux=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Dlibaudit=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Dx11_autolaunch=disabled
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
        # DESTDIR=$out redirects /etc and /var install paths under $out
        # (writable nix build dir) so the runtime paths stay as /etc/...
        # and /var/... per the --sysconfdir/--localstatedir above.
        script = ''
          DESTDIR=$out ninja -C build install
          # Flatten $out/$out/... concat from DESTDIR + --prefix.
          if [ -d "$out$out" ]; then
            cp -a $out$out/. $out/
            rm -rf $out/nix
          fi
        '';
      }
    ];

    meta = {
      description = "D-Bus — freedesktop.org message bus system";
      homepage = "https://www.freedesktop.org/wiki/Software/dbus/";
      license = "AFL-2.1";
    };
  }
