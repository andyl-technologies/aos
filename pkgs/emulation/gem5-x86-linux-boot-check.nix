##! Boots the actual fixed PC Linux guest without common-node admission
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  gem5-x86-linux-model-assets,
  python3,
  coreutils,
}: let
  # Bound guest progress separately from the measured native wall-time allowance.
  horizonSeconds = 4;
  slotWallSeconds = 2000;
  native = gem5-native-original-scope-foundation;
  assets = gem5-x86-linux-model-assets;
  manifest = "${assets}/share/crucible/gem5/x86-linux-assets.json";
  bootCheck = ./_gem5/x86-linux-native-boot-check.py;
  unitCheck = ./_gem5/x86-linux-native-boot-unit-check.py;
  compareBoots = ./_gem5/x86-linux-native-boot-compare.py;
in
  mkDerivation {
    pname = "gem5-x86-linux-boot-check";
    version = "1";
    outputs = ["out" "source"];

    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    buildDeps = [python3 coreutils];
    runtimeDeps = [native native.source assets assets.source];
    phases = [
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -I -B ${unitCheck} ${bootCheck}
          # Each slot starts a distinct native process and resource tree once.
          # A failed first attempt ends the check instead of renewing credit.
          for attempt in 1 2; do
            mkdir -m 700 "$PWD/native-root-$attempt"
            ${assets}/bin/gem5-x86-prepare "$PWD/native-root-$attempt" \
              > "prepared-data-$attempt.json"
            status=0
            ${coreutils}/bin/timeout --signal=TERM --kill-after=10s ${toString slotWallSeconds}s \
              ${native}/bin/gem5 --listener-mode=off --outdir="$PWD/native-root-$attempt" \
              ${bootCheck} ${assets.source}/x86-linux-bundle.py ${manifest} \
              "$PWD/prepared-data-$attempt.json" "$PWD/console-$attempt.bin" \
              "$PWD/boot-receipt-$attempt.json" ${toString horizonSeconds} > "native-boot-$attempt.log" 2>&1 || status=$?
            cat "native-boot-$attempt.log"
            if [ "$status" -ne 0 ]; then
              if [ -f "console-$attempt.bin" ]; then
                cat "console-$attempt.bin"
              fi
              exit "$status"
            fi
            test -s "boot-receipt-$attempt.json"
          done
          ${python3}/bin/python3 -I -B ${compareBoots} \
            boot-receipt-1.json console-1.bin boot-receipt-2.json console-2.bin \
            repeated-boot.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/gem5/checks" "$source"
          cp boot-receipt-1.json "$out/share/gem5/checks/x86-linux-pid1-boot.json"
          cp boot-receipt-2.json "$out/share/gem5/checks/x86-linux-pid1-second-boot.json"
          cp repeated-boot.json "$out/share/gem5/checks/x86-linux-two-fresh-boots.json"
          cp console-1.bin "$out/share/gem5/checks/x86-linux-first-console.bin"
          cp console-2.bin "$out/share/gem5/checks/x86-linux-second-console.bin"
          cp native-boot-1.log "$out/share/gem5/checks/x86-linux-first-native.log"
          cp native-boot-2.log "$out/share/gem5/checks/x86-linux-second-native.log"
          cp ${bootCheck} "$source/x86-linux-native-boot-check.py"
          cp ${unitCheck} "$source/x86-linux-native-boot-unit-check.py"
          cp ${compareBoots} "$source/x86-linux-native-boot-compare.py"
          cp ${./gem5-x86-linux-boot-check.nix} "$source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$source/LICENSE"
          ln -s ${native.source} "$source/native-corresponding-source"
          ln -s ${assets.source} "$source/asset-corresponding-source"
          ln -s "$source" "$out/share/corresponding-source"
        '';
      }
    ];
    meta = {
      description = "Runs the real fixed x86 Linux guest through both PID1 console markers, preserving actual native UART birth digests without capture or common-node qualification";
      license = "MIT";
    };
  }
