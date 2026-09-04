# Runs the same real-process settings checks used for local validation in a VM.
{
  testing,
  pkgs,
}: let
  script = pkgs.writeTextFile {
    name = "hub-settings-native-test";
    destination = "/hub-settings.py";
    text = builtins.readFile ../native/hub-settings.py;
  };
in
  testing.mkVMTest {
    name = "hub-settings";
    memory = 2048;
    rootfsDeps = [pkgs.aos pkgs.aos-hub pkgs.python3 pkgs.coreutils pkgs.iproute2 script];
    testScript = ''
      ${pkgs.iproute2}/sbin/ip link set lo up
      ${pkgs.coreutils}/bin/chroot --userspec=65534:65534 / \
        ${pkgs.python3}/bin/python3 ${script}/hub-settings.py \
          --hub-binary ${pkgs.aos-hub}/bin/aos-hub \
          --aos-binary ${pkgs.aos}/bin/aos \
          --require-assets
    '';
  }
