##! Mandatory native diagnostic controls against the full ALL source foundation
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  python3-3_12,
  coreutils,
  grep,
}: let
  foundation = gem5-native-original-scope-foundation;
  source = foundation.source;
  nativeCheck = ./_gem5/native-original-scope-check.py;
  diagnosticGuest = ./_gem5/native-diagnostic-guest.py;
  evidenceWriter = ./_gem5/native-original-scope-evidence.py;
in
  mkDerivation {
    pname = "gem5-native-original-scope-check";
    version = "1";

    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    buildDeps = [python3-3_12 coreutils grep];
    runtimeDeps = [foundation source];
    phases = [
      {
        name = "check";
        script = ''
          ${python3-3_12}/bin/python3 ${diagnosticGuest} diagnostic-fixed-loop.elf
          mkdir -p "$out/share/gem5/checks"
          for mode in owned unknown-bus changed-clock foreign-helper unarmed; do
            status=0
            ${foundation}/bin/gem5 --listener-mode=off --outdir="native-scope-$mode" \
              ${nativeCheck} diagnostic-fixed-loop.elf "$mode" \
              > "native-scope-$mode.log" 2>&1 || status=$?
            # Preserve the actual error even if Nix removes this failed tree.
            cat "native-scope-$mode.log"
            printf '%s\n' "$status" > "native-scope-$mode.status"
            if [ "$mode" = unarmed ]; then
              test "$status" -eq 126
            else
              test "$status" -eq 0
            fi
            grep '"schema":"crucible.gem5.diagnostic-original-native-ownership.v1"' \
              "native-scope-$mode.log" > "$out/share/gem5/checks/native-scope-$mode.json"
          done

          ${python3-3_12}/bin/python3 ${evidenceWriter} \
            ${foundation} ${source} ${./gem5-native-original-scope-check.nix} \
            ${nativeCheck} ${diagnosticGuest} "$out/share/gem5/checks/source-binding.json"
          # The mandatory check's closure co-retains both the actual ELF and
          # its complete matching source; these links grant no node authority.
          ln -s ${foundation} "$out/share/gem5/foundation"
          ln -s ${source} "$out/share/gem5/corresponding-source"
        '';
      }
    ];

    meta = {
      description = "Runs all five source-bound native diagnostic graph controls without granting source issuance, restore adoption or node readiness";
      license = "MIT";
    };
  }
