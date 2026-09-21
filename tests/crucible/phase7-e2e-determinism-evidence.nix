{
  pkgs,
  producerEvidence,
  reproducerEvidence,
  releaseSignOff,
}: let
  nativeRunner = ./_e2e-determinism-native-runner.sh;
in
  pkgs.mkDerivation {
    pname = "crucible-e2e-determinism-cross-host-evidence";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.grep
      pkgs.sed
    ];

    phases = [
      {
        name = "verify-cross-host-evidence";
        script = ''
          set -eu
          verified="$TMPDIR/verified"
          ${pkgs.bash}/bin/bash ${nativeRunner} verify-cross-host \
            ${producerEvidence} \
            ${reproducerEvidence} \
            ${releaseSignOff} \
            "$verified"

          mkdir -p "$out"
          cp -R ${producerEvidence} "$out/producer"
          cp -R ${reproducerEvidence} "$out/reproducer"
          cp ${releaseSignOff} "$out/release-sign-off.env"
          cp "$verified/command-journal.tsv" "$out/command-journal.tsv"
          cp "$verified/result" "$out/result"
          cp "$verified/canonical-results.tsv" "$out/canonical-results.tsv"
        '';
      }
    ];
  }
