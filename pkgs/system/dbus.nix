##! D-Bus — Message bus system
##! Note: dbus 1.14.x uses autotools, not meson (meson is 1.15.x+)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  expat,
  libselinux,
  audit,
  systemd,
  stdenv,
}: let
  version = "1.14.10";
in
  mkDerivation {
    pname = "dbus";
    inherit version;

    src = fetchurl {
      urls = [
        "https://dbus.freedesktop.org/releases/dbus/dbus-${version}.tar.xz"
      ];
      hash = "sha256-uh8h0r2dM52i1KqHgMCd8y/qh5mLc9ok9Jq53x42pQ8=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps =
      [expat]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [
          libselinux
          audit
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
        name = "configure";
        # --enable-systemd so dbus installs its user service/socket units and
        # sockets.target.wants link for systemd.packages consumers.
        # --sysconfdir=/etc so
        # baked-in config lookups go to /etc/dbus-1 on the running system,
        # not a read-only store path.
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --disable-tests \
            --disable-doxygen-docs \
            --disable-xml-docs \
            --${
            if stdenv.hostPlatform.isDarwin
            then "disable"
            else "enable"
          }-systemd \
            --enable-user-session \
            --disable-apparmor \
            --${
            if stdenv.hostPlatform.isDarwin
            then "disable"
            else "enable"
          }-selinux \
            --${
            if stdenv.hostPlatform.isDarwin
            then "disable"
            else "enable"
          }-libaudit \
            --without-x
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
        # DESTDIR=$out redirects /etc and /var install paths under $out
        # (writable nix build dir) so the runtime paths stay as /etc/...
        # and /var/... per the --sysconfdir/--localstatedir above.
        script = ''
          make install DESTDIR=$out
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
