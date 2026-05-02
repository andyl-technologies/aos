##! pkgs/system/dbus-conf.nix — aggregate dbus-1 configuration.
##!
##! Why: stock ${pkgs.dbus}/share/dbus-1/system.conf uses
##! <standard_system_servicedirs/>, which is baked at compile time to the
##! (empty) ${pkgs.dbus}/share/dbus-1/{services,system-services}. dbus-daemon
##! never sees ${pkgs.systemd}/share/dbus-1/system-services, so
##! org.freedesktop.systemd1 never makes it onto the system bus.
##!
##! This aggregator runs an XSL transform over the stock system.conf,
##! replacing the macro with explicit <servicedir>/<includedir> entries for
##! each contributor package. Modelled on nixpkgs' pkgs.makeDBusConf.
##!
##! The XSL stylesheets live under _dbus-conf-xsl/ — the leading underscore
##! tells discoverPackages (pkgs/default.nix) to skip the directory so it
##! isn't mistaken for a sub-package.
##!
##! Outer args are auto-filled by callPackage. The returned function takes
##! the per-deployment knobs and produces a derivation whose output has
##! $out/system.conf and $out/session.conf.
{
  runCommand,
  libxslt,
  dbus,
  lib,
}: {
  packages ? [],
  suidHelper ? "/bin/false",
  apparmor ? "disabled", # one of: enabled, disabled, required
}:
runCommand "aos-dbus-1"
{
  serviceDirectories = lib.concatStringsSep " " (map toString packages);
  inherit suidHelper apparmor;
  preferLocalBuild = true;
  allowSubstitutes = false;
  buildDeps = [libxslt];
  runtimeDeps = [dbus];
}
''
  set -eu
  mkdir -p "$out"

  # --nonet blocks DTD fetch over HTTP; --novalid skips DTD validation
  # entirely (AOS has no XML catalog setup hook). The XSL doesn't rely
  # on DTD-declared entities.
  ${libxslt}/bin/xsltproc --nonet --novalid \
    --stringparam serviceDirectories "$serviceDirectories" \
    --stringparam suidHelper          "$suidHelper" \
    --stringparam apparmor            "$apparmor" \
    ${./_dbus-conf-xsl/make-system-conf.xsl} \
    ${dbus}/share/dbus-1/system.conf \
    > "$out/system.conf"

  ${libxslt}/bin/xsltproc --nonet --novalid \
    --stringparam serviceDirectories "$serviceDirectories" \
    --stringparam apparmor            "$apparmor" \
    ${./_dbus-conf-xsl/make-session-conf.xsl} \
    ${dbus}/share/dbus-1/session.conf \
    > "$out/session.conf"

  # xsltproc returns 0 even when emitting an empty file in some failure
  # modes; defend against silent breakage.
  grep -q '[^[:space:]]' "$out/system.conf" || {
    echo "dbus-conf: $out/system.conf is empty - XSL likely broken." >&2
    exit 1
  }
  grep -q '[^[:space:]]' "$out/session.conf" || {
    echo "dbus-conf: $out/session.conf is empty - XSL likely broken." >&2
    exit 1
  }
''
