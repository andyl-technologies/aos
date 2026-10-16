# Keeps mandatory inode and xattr assertions on a genuine ext4 filesystem.
{
  pkgs,
  lib,
  testImage,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  workflow = lib.replaceStrings ["@SOURCE@" "@IMAGE@"] [
    "${pkgs.terrane.src}"
    "${testImage}"
  ] (builtins.readFile ./surface-presentation-ext4.sh);
in
  testing.mkVMTest {
    name = "terrane-surface-presentation-ext4";
    memory = 1024;
    rootfsDeps = [
      testImage
      pkgs.terrane.src
      pkgs.python3
      pkgs.coreutils
      pkgs.diffutils
      pkgs.util-linux
    ];
    testScript = workflow;
  }
