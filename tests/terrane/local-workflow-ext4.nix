# Exercises T1 deployment through the packaged local CLI and registered SDK
# checkout on actual guest ext4. This workflow is not the TEST-6 backend suite.
{
  pkgs,
  lib,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  workflow =
    lib.replaceStrings ["@TERRANE@"] ["${pkgs.terrane}/bin/terrane"]
    (builtins.readFile ./local-workflow-ext4/workflow.sh);

  vmTest = testing.mkVMTest {
    name = "terrane-local-workflow-ext4";
    memory = 1024;
    rootfsDeps = [
      pkgs.terrane
      pkgs.coreutils
      pkgs.diffutils
      pkgs.util-linux
    ];
    testScript = workflow;
  };
in
  vmTest.overrideAttrs (attributes: {
    phases =
      attributes.phases
      ++ [
        {
          name = "retain-workflow-evidence";
          script = ''
            # The guest's operation logs and persisted repository live on this
            # writable image, not in the immutable rootfs used to boot it.
            cp --sparse=always rootfs.img "$out/rootfs.img"
            cp "$TMPDIR/vm_config.json" "$out/vm-config.json"
            printf '%s\n' '${pkgs.terrane}/bin/terrane' > "$out/terrane-binary"
          '';
        }
      ];
  })
