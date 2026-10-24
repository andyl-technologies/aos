# Identity and byte/allocation regressions for reusable VM artifacts.
{
  pkgs,
  lib,
}: let
  vm = import ../../lib/testing/vm.nix {inherit pkgs lib;};
  first = vm.mkVMTest {
    name = "first";
    rootfsDeps = [];
    testScript = "true";
  };
  second = vm.mkVMTest {
    name = "second";
    rootfsDeps = [];
    testScript = "false";
  };
  dependency = vm.mkVMTest {
    name = "first";
    rootfsDeps = [pkgs.jq];
    testScript = "true";
  };
  devVm = import ../../lib/testing/vm.nix {
    inherit lib;
    pkgs = pkgs // {sharedImageCacheDir = "/aos-build-cache/images";};
  };
  devTest = name: script: deps:
    devVm.mkVMTest {
      inherit name;
      testScript = script;
      rootfsDeps = deps;
    };
  devFirst = devTest "first" "true" [];
  devSecond = devTest "second" "false" [];
  devDependency = devTest "first" "true" [pkgs.jq];
  shell = ((import ../../flake.nix).outputs {}).devShells.${pkgs.coreutils.system}.cargo;
in
  assert first.passthru.rootfs.drvPath == second.passthru.rootfs.drvPath;
  assert first.passthru.testInput.drvPath != second.passthru.testInput.drvPath;
  assert first.passthru.rootfs.drvPath != dependency.passthru.rootfs.drvPath;
  assert devFirst.passthru.rootfs.drvPath == devSecond.passthru.rootfs.drvPath;
  assert devFirst.passthru.rootfs.drvPath != devDependency.passthru.rootfs.drvPath;
  # Direct source-path contexts have `path = true`; tools use output contexts.
  # This rejects the previous ./. interpolation even after Nix renamed the tree.
  assert builtins.all (context: !(context.path or false)) (builtins.attrValues (builtins.getContext shell.shellHook));
    pkgs.mkDerivation {
      pname = "vm-artifacts-check";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.python3 pkgs.bash (pkgs.ninja.passthru.withCommandShell pkgs.bash)];
      phases = [
        {
          name = "check";
          script = ''
            # Exercise the opt-in source-built shell with an actual Ninja edge.
            cat > build.ninja <<'NINJA'
            rule shell
              command = printf shell-ok > $out
            build ninja-result: shell
            NINJA
            ninja
            test "$(cat ninja-result)" = shell-ok

            export PYTHONDONTWRITEBYTECODE=1
            export PYTHONPATH=${../../pkgs/tools/aos/aos-test-driver}
            ${pkgs.python3}/bin/python3 -m unittest discover \
              -s ${../../pkgs/tools/aos/aos-test-driver/tests} -v

            # Partition insertion must preserve existing GPT bytes and sparse tails.
            truncate -s 64M source.img
            printf 'root-data' | dd of=source.img bs=1 seek=1048576 conv=notrunc status=none
            truncate -s 128M disk.img
            printf 'gpt-header' | dd of=disk.img conv=notrunc status=none
            dd if=source.img of=disk.img bs=1M seek=4 conv=notrunc,sparse status=none
            dd if=disk.img of=extracted.img bs=1M skip=4 count=64 status=none
            cmp source.img extracted.img
            test "$(head -c 10 disk.img)" = gpt-header
            test "$(stat -c %s disk.img)" -eq $((128 * 1024 * 1024))
            test "$(( $(stat -c %b disk.img) * 512 ))" -lt $((3 * 1024 * 1024))
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
