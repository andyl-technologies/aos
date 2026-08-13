##! modules/image/_budget-check.nix — per-image artifact contract check
{
  config,
  lib,
  pkgs,
  image,
  rootfs,
  uki,
  name,
}: let
  budgets = config.aos.image.budgets;
  mib = 1048576;
  verityEnabled = config.aos.security.verity.enable;
in
  pkgs.mkDerivation ({
      pname = "aos-image-${name}-budget-check";
      version = config.aos.system.version;
      src = null;

      outputChecks = {};
      exportReferencesGraph.runtime = [config.system.build.toplevel];
      # The raw publication artifact performs the authoritative ESP-content
      # and fixed-layout checks. Keeping it as an input makes this focused
      # check a complete release gate instead of a partial parallel policy.
      buildDeps = [pkgs.coreutils pkgs.jq image];
      dontStrip = true;
      dontNukeRefs = true;

      ROOT_SIZE_FILE = "${rootfs}/rootfs-size-bytes";
      INITRD = "${config.system.build.initrd}/initrd.img";
      UKI = uki;
      MAX_ROOT_BYTES = toString (budgets.maxRootMiB * mib);
      MAX_INITRD_BYTES = toString (budgets.maxInitrdMiB * mib);
      MAX_UKI_BYTES = toString (budgets.maxUkiMiB * mib);
      MAX_RUNTIME_CLOSURE_BYTES = toString (budgets.maxRuntimeClosureMiB * mib);

      phases = [
        {
          name = "check";
          script = ''
            set -eu
            mkdir -p "$out"

            root_bytes=$(cat "$ROOT_SIZE_FILE")
            initrd_bytes=$(stat -c %s "$INITRD")
            uki_bytes=$(stat -c %s "$UKI")
            closure_bytes=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
            ${lib.optionalString verityEnabled ''verity_bytes=$(stat -c %s ${rootfs}/root.verity)''}
            ${lib.optionalString (!verityEnabled) ''verity_bytes=0''}

            check_budget() {
              label=$1
              actual=$2
              maximum=$3
              if [ "$actual" -gt "$maximum" ]; then
                echo "$label is $actual bytes; image contract permits at most $maximum bytes" >&2
                exit 1
              fi
            }

            check_budget "root image" "$root_bytes" "$MAX_ROOT_BYTES"
            check_budget "initrd" "$initrd_bytes" "$MAX_INITRD_BYTES"
            check_budget "UKI" "$uki_bytes" "$MAX_UKI_BYTES"
            check_budget "runtime closure" "$closure_bytes" "$MAX_RUNTIME_CLOSURE_BYTES"
            check_budget "verity tree" "$verity_bytes" "${toString (budgets.maxVerityMiB * mib)}"

            jq -S -n \
              --arg name ${lib.escapeShellArg name} \
              --argjson rootBytes "$root_bytes" \
              --argjson initrdBytes "$initrd_bytes" \
              --argjson ukiBytes "$uki_bytes" \
              --argjson verityBytes "$verity_bytes" \
              --argjson runtimeClosureBytes "$closure_bytes" \
              --argjson maxRootMiB ${toString budgets.maxRootMiB} \
              --argjson maxInitrdMiB ${toString budgets.maxInitrdMiB} \
              --argjson maxUkiMiB ${toString budgets.maxUkiMiB} \
              --argjson maxVerityMiB ${toString budgets.maxVerityMiB} \
              --argjson maxEspMiB ${toString budgets.maxEspMiB} \
              --argjson maxRuntimeClosureMiB ${toString budgets.maxRuntimeClosureMiB} \
              '{
                schema: "aos.image-budget-report/v1",
                name: $name,
                actual: {
                  rootBytes: $rootBytes,
                  initrdBytes: $initrdBytes,
                  ukiBytes: $ukiBytes,
                  verityBytes: $verityBytes,
                  runtimeClosureBytes: $runtimeClosureBytes
                },
                maximumMiB: {
                  root: $maxRootMiB,
                  initrd: $maxInitrdMiB,
                  uki: $maxUkiMiB,
                  verity: $maxVerityMiB,
                  esp: $maxEspMiB,
                  runtimeClosure: $maxRuntimeClosureMiB
                }
              }' > "$out/report.json"
          '';
        }
      ];

      meta.description = "Artifact and runtime-closure budgets for the ${name} golden image";
    }
    // lib.optionalAttrs verityEnabled {
      VERITY = "${rootfs}/root.verity";
    })
