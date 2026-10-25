# Builds the disk-backed, networkless environment for native prerequisite checks.
{
  pkgs,
  lib,
}: let
  testing = import ../../../lib/testing {inherit pkgs lib;};
  imageMetadata = import ../../../lib/build/image-metadata.nix {inherit pkgs;};
  guest = pkgs.writeTextFile {
    name = "terrane-native-builder-guest";
    destination = "/bin/native-builder-guest";
    executable = true;
    text = "#!${pkgs.bash}/bin/bash\n" + builtins.readFile ./guest.sh;
  };
  rootfs = testing.mkFirecrackerRootfs {
    rootfsDeps = [pkgs.nix pkgs.socat pkgs.e2fsprogs guest];
  };
  input = pkgs.mkDerivation {
    pname = "terrane-native-builder-input";
    version = "0";
    src = null;
    buildDeps = [pkgs.e2fsprogs pkgs.fakeroot pkgs.python3];
    phases = [
      {
        name = "input";
        script = ''
          mkdir -p input "$out"
          cp ${rootfs.REGINFO}/registration input/registration
          printf '%s\n' 'set -e' 'exec ${guest}/bin/native-builder-guest' > input/test
          ${imageMetadata.environment}
          IMAGE_UUID=$(${imageMetadata.command} tree aos-native-builder-input input)
          fakeroot -- mkfs.ext4 ${imageMetadata.ext4Options} -d input -L aos-native-builder \
            -m 0 -q "$out/input.img" 32M
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "terrane-native-builder-environment";
    version = "0";
    src = null;
    # A fresh explicit nonce requires an actual build on every qualification run.
    passthru.probe = {nonce}: import ./probe.nix {inherit pkgs nonce;};
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "assemble";
        script = ''
          mkdir -p "$out"
          cp ${./run.py} "$out/run.py"
          cp ${./proxy.py} "$out/proxy.py"
          ln -s ${rootfs}/root.img "$out/root.img"
          ln -s ${input}/input.img "$out/input.img"
          ln -s ${pkgs.linux.vmlinux}/boot "$out/kernel"
          ln -s ${pkgs.firecracker}/bin/firecracker "$out/firecracker"
          ln -s ${pkgs.python3}/bin/python3 "$out/python3"
          ln -s ${pkgs.e2fsprogs}/bin/mkfs.ext4 "$out/mkfs.ext4"
          ln -s ${pkgs.bash}/bin/bash "$out/bash"
          ln -s ${pkgs.coreutils}/bin/cp "$out/cp"
          ln -s ${pkgs.util-linux}/bin/findmnt "$out/findmnt"
        '';
      }
    ];
  }
