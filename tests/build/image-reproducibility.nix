# Independent ordinary builders and cold recipes must emit identical bytes.
{
  pkgs,
  lib,
}: let
  closureInfoFor = lib.build.closureInfo {inherit pkgs;};
  fixture = pkgs.mkDerivation {
    pname = "image-metadata-fixture";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/host-deployment" "$out/lib/modules/fixture"
          printf fixture > "$out/host-deployment/identity"
        '';
      }
    ];
  };
  kernel = {
    package = fixture;
    configuration = {
      release = "fixture";
      moduleTree = "${fixture}/lib/modules/fixture";
    };
  };
  system.config = {
    environment.systemPackages = [];
    system.build = {
      toplevel = fixture;
      managerConfiguration = null;
    };
    aos = {
      configurationLower.enable = false;
      filesystems.zfs.datasets = {};
      kernel = {
        selected = kernel;
        modulePackages = [];
      };
      manager.selected.configuration.rootfs = null;
      boot = {
        stageInputPaths.host.bundle = "/usr/lib/aos/host/deployment";
        stageInputPaths.receivedInitrd.bundle = "/usr/lib/aos/initrd/deployment";
        initrd.abilityHandoff.enable = false;
      };
    };
  };
  recipe = import ../../lib/testing/image-recipe.nix {
    inherit lib;
    pkgs = pkgs // {sharedImageCacheDir = "/unused-image-reproducibility-cache";};
  };
  root = run: format: shrink: payload: runtime:
    import ../../pkgs/system/_systemd-abilities/platform/_rootfs-builder.nix {
      inherit lib system kernel closureInfoFor;
      pkgs =
        pkgs
        // {
          mkDerivation =
            if runtime
            then recipe {}
            else pkgs.mkDerivation;
        };
      pname = "image-reproducibility-${run}";
      fsType = format;
      shrinkToFit = shrink;
      minSizeMiB = 64;
      headroomMiB = 8;
      postPopulate = ''
        printf '%s' ${lib.escapeShellArg payload} > rootfs/payload
        chmod 0640 rootfs/payload
        ln -s payload rootfs/payload-link
        ln rootfs/payload rootfs/payload-hardlink
      '';
    };
  disk = run: runtime:
    import ../../pkgs/system/_systemd-abilities/testing/disk.nix {
      inherit lib closureInfoFor;
      mkImageRecipe =
        if runtime
        then recipe
        else null;
      packages = pkgs // {systemd = fixture;};
    } {
      inherit system;
      name = "repro-${run}";
      varSizeMiB = 16;
    };
  firecracker = import ../../lib/testing/firecracker.nix {inherit pkgs lib;};
  devFirecracker = import ../../lib/testing/firecracker.nix {
    inherit lib;
    pkgs = pkgs // {sharedImageCacheDir = "/unused-image-reproducibility-cache";};
  };
  input = firecracker.mkFirecrackerTestInput "printf reproducible";
in
  pkgs.mkDerivation {
    pname = "image-reproducibility-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.python3 pkgs.coreutils pkgs.e2fsprogs pkgs.util-linux];
    phases = [
      {
        name = "check";
        script = ''
          export PYTHONPATH=${../../pkgs/tools/aos/aos-test-driver}
          export PYTHONDONTWRITEBYTECODE=1
          python3 ${./image-reproducibility.py} \
            --root ${root "first" "ext4" false "payload" false} \
            --root-again ${root "second" "ext4" false "payload" false} \
            --changed ${root "changed" "ext4" false "different" false} \
            --shrunk ${root "shrink-first" "ext4" true "payload" false} \
            --shrunk-again ${root "shrink-second" "ext4" true "payload" false} \
            --erofs ${root "erofs-first" "erofs" false "payload" false} \
            --erofs-again ${root "erofs-second" "erofs" false "payload" false} \
            --recipe ${root "runtime" "ext4" false "payload" true} \
            --disk ${disk "first" false} --disk-again ${disk "second" false} \
            --disk-recipe ${disk "runtime" true} \
            --input ${input} --input-again ${input.override {REPRO_RUN = "second";}} \
          --headless ${firecracker.mkFirecrackerRootfs {rootfsDeps = [];}} \
          --headless-recipe ${devFirecracker.mkFirecrackerRootfs {
            rootfsDeps = [];
            development = true;
          }} \
          --metadata ${../../lib/build/image-metadata.py}
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
