##! qemu-img — standalone QEMU disk image utility
{
  lib,
  mkDerivation,
  stdenv,
  buildPackages,
  qemu,
  glib,
  zlib,
}: let
  version = qemu.version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  darwinSigner =
    if isDarwinCross
    then
      import ./_darwin-signer.nix {
        inherit (buildPackages) mkDerivation fetchurl gnumake pkg-config openssl;
      }
    else null;
in
  mkDerivation {
    pname = "qemu-img";
    inherit version;
    src = null;

    # qemu is only the source of the already-built utility. The scrub phase
    # removes its compiled-in installation prefix so this small runtime tool
    # does not retain the complete system emulator.
    # The install script references the already-built target artifact directly.
    # Do not splice QEMU into the native tool role for Darwin cross builds.
    buildDeps =
      lib.optional (!isDarwinCross) qemu
      ++ lib.optional isDarwinCross darwinSigner;
    runtimeDeps = [glib zlib];
    propagatedDeps = [];
    disallowedReferences = [qemu];
    # The source utility is already stripped. Darwin's copied binary must be
    # scrubbed and re-signed in that order, so skip the later generic passes.
    dontStrip = lib.optionalString isDarwinCross "1";
    dontNukeRefs = lib.optionalString isDarwinCross "1";

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp ${qemu}/bin/qemu-img "$out/bin/qemu-img"
          ${lib.optionalString isDarwinCross ''
            nuke-refs \
              -e "$out" \
              -e ${glib} \
              -e ${zlib} \
              "$out/bin/qemu-img"
            ldid -S "$out/bin/qemu-img"
            ldid -e "$out/bin/qemu-img" >/dev/null
          ''}
        '';
      }
    ];

    meta = {
      description = "QEMU disk image utility without the system emulators";
      homepage = "https://www.qemu.org";
      license = "GPL-2.0-only";
    };
  }
