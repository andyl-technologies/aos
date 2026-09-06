##! fuse3 — Filesystem in Userspace library and mount helper
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  util-linux,
}: let
  version = "3.17.4";
in
  mkDerivation {
    pname = "fuse3";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/libfuse/libfuse/archive/refs/tags/fuse-${version}.tar.gz"];
      hash = "sha256-3SHRVFwF5zraWUuT/lkzUbfb8QlA/ZO5NLk5VRMQizQ=";
    };

    buildDeps = [meson ninja pkg-config python3];
    runtimeDeps = [util-linux];
    propagatedDeps = [];
    mesonFlags = builtins.concatStringsSep " " [
      "-Duseroot=false"
      "-Dinitscriptdir="
      "-Dexamples=false"
      "-Dtests=false"
      "-Dudevrulesdir=${builtins.placeholder "out"}/lib/udev/rules.d"
    ];

    postPatch = ''
      sed -i         -e "s|/bin/mount|${util-linux}/bin/mount|g"         -e "s|/bin/umount|${util-linux}/bin/umount|g"         lib/mount_util.c
      sed -i "s|/bin/sh|$CONFIG_SHELL|g" util/mount.fuse.c
    '';

    preBuild = ''export PYTHONPATH="${meson}/lib/python3/site-packages"'';
    preInstall = ''export PYTHONPATH="${meson}/lib/python3/site-packages"'';

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-fuse3";
        libraries = [self];
        source = ''
          #define FUSE_USE_VERSION 35
          #include <fuse3/fuse.h>
          int main(void) {
            return fuse_version() > 0 ? 0 : 1;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-fuse3";
        tool = self;
        command = "fusermount3 --version";
      };
    };

    meta = {
      description = "Reference library and tools for Filesystem in Userspace";
      homepage = "https://github.com/libfuse/libfuse";
      license = "GPL-2.0-only AND LGPL-2.1-only";
    };
  }
