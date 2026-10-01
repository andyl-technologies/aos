##! Runs actual direct publication guard journals across persistent workerd restarts.
##! The test provider supplies explicit effects; this cannot qualify hosted R2.
{
  mkDerivation,
  callPackage,
  nodejs,
  workerd-source,
  bash,
  coreutils,
}: let
  dist = callPackage ./aos-hub-worker-dist.nix {cargoFeatures = "do-e2e";};
  driver = ./aos-hub-direct-guard-e2e.mjs;
in
  mkDerivation {
    pname = "aos-hub-direct-guard-e2e";
    version = "0.1.0";
    src = null;
    runtimeDeps = [dist nodejs workerd-source bash coreutils];
    passthru.workerDist = dist;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos-hub-direct-guard-e2e"
          cp ${driver} "$out/share/aos-hub-direct-guard-e2e/driver.mjs"
          cat > "$out/bin/aos-hub-direct-guard-e2e" <<EOF
          #!${bash}/bin/bash
          set -euo pipefail
          export AOS_DIRECT_GUARD_E2E_DIST=${dist}
          export AOS_DIRECT_GUARD_E2E_WORKERD=${workerd-source}/bin/workerd
          evidence=\''${1:-\$(${coreutils}/bin/mktemp -d -t aos-direct-guard-e2e.XXXXXXXX)}
          exec ${nodejs}/bin/node "$out/share/aos-hub-direct-guard-e2e/driver.mjs" "\$evidence"
          EOF
          chmod +x "$out/bin/aos-hub-direct-guard-e2e"
        '';
      }
    ];
    meta.description = "Persistent direct-upload physical guard journal runner";
  }
