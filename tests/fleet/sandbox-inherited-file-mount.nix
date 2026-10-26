# Component proof for inherited file mounts outside a private mount namespace.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  ...
} @ args: let
  installedSystem = (import ./sandbox-host-phase0-readiness.nix args).machines.vm.system;
  installedKernel = installedSystem.config.system.build.kernel;

  probe = pkgs.mkCargoPackage {
    pname = "aos-inherited-file-mount-test";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-linux --test inherited-file-mount --features kernel-tests"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.jq];
    runtimeDeps = [];
    postBuild = import ./_cargo-libtest-artifact.nix {
      inherit lib pkgs;
      crate = "aos-sandbox-linux";
      target = "inherited-file-mount";
      kind = "test";
      destination = "native-tests/inherited-file-mount";
    };
    postInstall = ''
      install -D -m 0755 native-tests/inherited-file-mount "$out/bin/inherited-file-mount"
    '';
  };

  script = pkgs.writeTextFile {
    name = "aos-inherited-file-mount-fixture";
    destination = "/fixture";
    text = ''
      set -eu
      fixture_root=$(mktemp -d /var/lib/aos-inherited-file-mount.XXXXXX)
      fixture_mounted=0
      cleanup() {
        exec 3<&-
        exec 4<&-
        if [ "$fixture_mounted" -eq 1 ]; then
          umount "$fixture_root/read-only"
        fi
        rm -rf "$fixture_root"
      }
      trap cleanup EXIT

      printf immutable > "$fixture_root/read-only"
      printf mutable > "$fixture_root/writable"
      mount --bind "$fixture_root/read-only" "$fixture_root/read-only"
      fixture_mounted=1
      mount -o remount,bind,ro "$fixture_root/read-only"
      exec 3< "$fixture_root/read-only"
      exec 4< "$fixture_root/writable"

      # Cloning changes namespace mount IDs, but the open files keep their
      # original mounts. Writable originals must continue to fail the guard.
      ${pkgs.util-linux}/bin/unshare --mount --propagation private \
        ${probe}/bin/inherited-file-mount \
        "$fixture_root/read-only" "$fixture_root/writable"
      exec 3<&-
      exec 4<&-
    '';
  };

  fixtureSystem = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [probe script pkgs.util-linux];
      aos.kernel._extraConfigFragments = lib.mkForce installedSystem.config.aos.kernel._extraConfigFragments;
    }
  ];
  system =
    if toString fixtureSystem.config.system.build.kernel == toString installedKernel
    then fixtureSystem
    else throw "inherited-file mount proof must use the installed Host kernel";
in {
  name = "sandbox-inherited-file-mount";
  timeout = 300;
  bootTimeout = 180;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    result = vm.succeed(
        "${pkgs.util-linux}/bin/unshare --mount --propagation private "
        "${pkgs.bash}/bin/bash ${script}/fixture",
        timeout=60,
    )
    assert "inherited mount basics preserve read-only and writable rejection: PASS" in result, result
  '';
}
