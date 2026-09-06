##! pm-utils — Suspend and resume hook framework
{
  mkDerivation,
  fetchurl,
  gnumake,
  coreutils,
  grep,
  util-linux,
  kmod,
  procps-ng,
  kbd,
  dbus,
}: let
  version = "1.4.1";
  runtimePath = "${coreutils}/bin:${grep}/bin:${util-linux}/bin:${util-linux}/sbin:${kmod}/bin:${procps-ng}/bin:${procps-ng}/sbin:${kbd}/bin:${dbus}/bin";
in
  mkDerivation {
    pname = "pm-utils";
    inherit version;

    src = fetchurl {
      urls = ["https://pm-utils.freedesktop.org/releases/pm-utils-${version}.tar.gz"];
      hash = "sha256-jtiZAyhm2IspM6HTTMdeiuQtzeIOHMIYNrqq49Q3DAs=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [coreutils grep util-linux kmod procps-ng kbd dbus];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pm-utils-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          find . -type f | while read -r script; do
            first=$(head -n 1 "$script" 2>/dev/null || true)
            case "$first" in
              '#!'*) sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$script" ;;
            esac
          done
          sed -i 's|/sbin:/usr/sbin:/bin:/usr/bin|$PATH:${runtimePath}|' pm/pm-functions.in
          sed -i 's|tr |${coreutils}/bin/tr |' src/pm-action.in
          sed -i 's|/bin/uname|${coreutils}/bin/uname|' pm/sleep.d/00logging
          sed -i 's|/sbin/hwclock|${util-linux}/sbin/hwclock|' pm/sleep.d/90clock
          sed -i '/@HAVE_XMLTO_TRUE@/s/@HAVE_XMLTO_TRUE@//' man/Makefile.in
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out" --sysconfdir="$out/etc"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/pm-is-supported" --help >/dev/null 2>&1 || test $? -eq 1
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-pm-utils";
        tool = self;
        command = "test -x /usr/sbin/pm-suspend && test -x /usr/bin/pm-is-supported";
      };
    };

    meta = {
      description = "Coordinates suspend and resume hooks for Linux systems";
      homepage = "https://pm-utils.freedesktop.org/";
      license = "GPL-2.0-or-later";
      mainProgram = "pm-suspend";
    };
  }
