##! Production native generation retention and source replay in an isolated store.
{pkgs, lib ? import ../default.nix {system = pkgs.bash.system;}}: let
  fixture = import ../../tests/effects/deployment-fixture.nix {inherit pkgs lib;};
  inputs = lib.build.closureInfo {inherit pkgs;} {
    pname = "native-source-gc-inputs";
    rootPaths = [fixture];
  };
  driver = pkgs.aos-package-evaluation-driver;
in
  pkgs.mkDerivation {
    pname = "config-source-gc";
    version = "0";
    src = null;
    buildDeps = [driver pkgs.coreutils pkgs.nix inputs];
    phases = [{
      name = "check";
      script = ''
        set -eu
        mkdir -p "$out"
        isolated_root="$TMPDIR/native-source-gc-store"
        isolated_store="local?root=$isolated_root"
        profile="$TMPDIR/native-source-gc-profile/system"
        mkdir -p "$isolated_root/nix/store" "$profile"
        while IFS= read -r store_path; do
          cp -a --no-preserve=ownership "$store_path" "$isolated_root/nix/store/"
        done < ${inputs}/store-paths
        ${pkgs.nix}/bin/nix-store --store "$isolated_store" --init
        ${pkgs.nix}/bin/nix-store --store "$isolated_store" --load-db < ${inputs}/registration
        export AOS_NIX_EVAL_STORE="$isolated_store"
        export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
        export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate
        # The production NixStore owns every indirect root. No handcrafted
        # profile layout or mock module-library evaluator participates here.
        if ! ${pkgs.coreutils}/bin/timeout 180 \
          ${driver}/bin/package_deployment_check --source-gc "$profile" \
          ${fixture}/fixture.json ${pkgs.nix}/bin/nix-store \
          > "$out/acceptance.log" 2> "$out/acceptance.stderr"; then
          cat "$out/acceptance.stderr" >&2
          exit 1
        fi
        test -s "$profile/deployment/retained-deployment.json"
        cp "$profile/deployment/retained-deployment.json" "$out/deployment.json"
        echo PASS > "$out/result"
      '';
    }];
  }
