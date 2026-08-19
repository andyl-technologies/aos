##! qemu-img — standalone QEMU disk image utility
{
  mkDerivation,
  qemu,
  glib,
  zlib,
}: let
  version = qemu.version;
in
  mkDerivation {
    pname = "qemu-img";
    inherit version;
    src = null;

    # qemu is only the source of the already-built utility. The scrub phase
    # removes its compiled-in installation prefix so this small runtime tool
    # does not retain the complete system emulator.
    buildDeps = [qemu];
    runtimeDeps = [glib zlib];
    propagatedDeps = [];
    disallowedReferences = [qemu];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp ${qemu}/bin/qemu-img "$out/bin/qemu-img"
        '';
      }
    ];

    meta = {
      description = "QEMU disk image utility without the system emulators";
      homepage = "https://www.qemu.org";
      license = "GPL-2.0-only";
    };
  }
