##! Two bounded fresh ARM Linux PID1 boots, without common-node admission
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  gem5-arm-linux-model-assets,
  python3,
  coreutils,
}: let
  # Existing ARM driver fixtures specify this horizon and wall bound. Neither
  # source precedent nor the x86 observation proves ARM will reach PID1 in it.
  horizonSeconds = 3;
  slotWallSeconds = 1800;
  native = gem5-native-original-scope-foundation;
  assets = gem5-arm-linux-model-assets;
  manifest = "${assets}/share/crucible/gem5/arm-linux-assets.json";
  names = [
    "linux-native-boot-common.py"
    "arm-linux-native-boot-check.py"
    "arm-linux-native-boot-compare.py"
    "arm-linux-native-boot-unit-check.py"
  ];
  helpers = builtins.path {
    path = ./_gem5;
    name = "gem5-arm-linux-boot-checks";
    filter = path: type:
      type == "directory" && builtins.baseNameOf path == "_gem5"
      || builtins.elem (builtins.baseNameOf path) names;
  };
in
  mkDerivation {
    pname = "gem5-arm-linux-boot-check";
    version = "1";
    outputs = ["out" "source"];
    platformSupport = {
      build = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    buildDeps = [python3 coreutils];
    runtimeDeps = [native native.source assets assets.source];
    phases = [
      {
        name = "check";
        script = ''
          ulimit -c 0
          ${python3}/bin/python3 -I -B ${helpers}/arm-linux-native-boot-unit-check.py ${helpers}
          for attempt in 1 2; do
            mkdir -m 700 "$PWD/native-root-$attempt"
            ${assets}/bin/gem5-arm-prepare "$PWD/native-root-$attempt" > "prepared-data-$attempt.json"
            status=0
            ${coreutils}/bin/timeout --signal=TERM --kill-after=10s ${toString slotWallSeconds}s \
              ${native}/bin/gem5 --listener-mode=off --outdir="$PWD/native-root-$attempt" \
              ${helpers}/arm-linux-native-boot-check.py \
              ${assets.source}/arm-linux-bundle.py ${manifest} \
              "$PWD/prepared-data-$attempt.json" "$PWD/console-$attempt.bin" \
              "$PWD/boot-receipt-$attempt.json" ${toString horizonSeconds} \
              > "native-boot-$attempt.log" 2>&1 || status=$?
            cat "native-boot-$attempt.log"
            if [ "$status" -ne 0 ]; then
              if [ -f "console-$attempt.bin" ]; then
                cat "console-$attempt.bin"
              fi
              exit "$status"
            fi
            test -s "boot-receipt-$attempt.json"
          done
          ${python3}/bin/python3 -I -B ${helpers}/arm-linux-native-boot-compare.py \
            boot-receipt-1.json console-1.bin boot-receipt-2.json console-2.bin repeated-boot.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/gem5/checks" "$source"
          cp boot-receipt-1.json "$out/share/gem5/checks/arm-linux-pid1-boot.json"
          cp boot-receipt-2.json "$out/share/gem5/checks/arm-linux-pid1-second-boot.json"
          cp repeated-boot.json "$out/share/gem5/checks/arm-linux-two-fresh-boots.json"
          cp console-1.bin "$out/share/gem5/checks/arm-linux-first-console.bin"
          cp console-2.bin "$out/share/gem5/checks/arm-linux-second-console.bin"
          cp native-boot-1.log "$out/share/gem5/checks/arm-linux-first-native.log"
          cp native-boot-2.log "$out/share/gem5/checks/arm-linux-second-native.log"
          cp ${helpers}/*.py "$source/"
          cp ${./gem5-arm-linux-boot-check.nix} "$source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$source/LICENSE"
          ln -s ${native.source} "$source/native-corresponding-source"
          ln -s ${assets.source} "$source/asset-corresponding-source"
          ln -s "$source" "$out/share/corresponding-source"
        '';
      }
    ];
    meta = {
      description = "Runs two real bounded VExpress ARM Linux guests through both PID1 markers and compares actual native UART observations, without capture or common-node qualification";
      license = "MIT";
    };
  }
