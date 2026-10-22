# Distinct assertions deliberately share the same guest base image.
{
  pkgs,
  lib,
}: let
  vm = import ../../lib/testing/vm.nix {inherit pkgs lib;};
  test = name: message:
    vm.mkVMTest {
      inherit name;
      rootfsDeps = [];
      testScript = ''
        test -r /run/aos-test-input/test
        test "$(cat /proc/1/comm)" = init
        echo '${message}'
      '';
    };
in {
  first = test "artifact-input-first" "FIRST_ASSERTIONS_EXECUTED";
  second = test "artifact-input-second" "SECOND_ASSERTIONS_EXECUTED";
}
