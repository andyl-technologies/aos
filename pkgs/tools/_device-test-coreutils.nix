##! Dynamically linked coreutils for LD_PRELOAD-based device replay tests.
{
  callPackage,
  mkDerivation,
  lib,
  gettext,
  acl,
  attr,
  libcap,
  gmp,
  openssl,
  libselinux,
}:
callPackage ../base/coreutils.nix {
  mkDerivation = attributes:
    mkDerivation (attributes
      // {
        pname = "coreutils-device-tests";
        # The public native coreutils is a static bootstrap artifact. Device
        # replay needs this source build so libc calls can be intercepted.
        configureFlags = lib.replaceStrings ["--disable-nls"] ["--enable-nls"] attributes.configureFlags;
        buildDeps = attributes.buildDeps ++ [gettext];
        runtimeDeps = [acl attr libcap gmp openssl libselinux];
      });
}
