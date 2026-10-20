##! Read-only native production evaluation, schema validation, and determinism.
{
  pkgs,
  lib,
  mkSystem,
  fixture ? import ../../tests/effects/deployment-fixture.nix {inherit pkgs lib;},
  inputs ?
    import ../build/closure-info.nix {inherit pkgs lib;} {
      pname = "native-config-evaluation-inputs";
      rootPaths = [fixture];
    },
  driver ? pkgs.aos-package-evaluation-driver,
}: let
  policyChecks = import ../../tests/effects/configuration-policy.nix;
in
  assert builtins.all (value: value == true) (builtins.attrValues policyChecks);
    pkgs.mkDerivation {
      pname = "config-eval-check";
      version = "0";
      src = null;
      buildDeps = [driver pkgs.coreutils pkgs.diffutils pkgs.jq pkgs.nix inputs];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            mkdir -p "$out"
            evaluation_store_root="$TMPDIR/evaluation-store"
            evaluation_store="local?root=$evaluation_store_root"
            mkdir -p "$evaluation_store_root/nix/store"
            while IFS= read -r store_path; do
              cp -a --no-preserve=ownership "$store_path" "$evaluation_store_root/nix/store/"
            done < ${inputs}/store-paths
            ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --init
            ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --load-db < ${inputs}/registration
            # The writable store root changes physical storage only; retained
            # descriptors and their Nix paths keep the canonical logical store.
            export AOS_NIX_STORE_DIR=/nix/store
            export AOS_NIX_EVAL_STORE="$evaluation_store"
            export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
            export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate

            # An explicit Nix suite must suffice even when PATH cannot supply
            # evaluator tools. This also exercises Nix's multicall entry points.
            for evaluation in first second; do
              echo "Checking native read-only evaluation: $evaluation"
              if ! PATH=/no-evaluator-on-path ${pkgs.coreutils}/bin/timeout 60 \
                ${driver}/bin/package_deployment_check --evaluate-only \
                ${fixture}/fixture.json ${pkgs.nix}/bin/nix-store \
                > "$out/$evaluation.json" 2> "$out/$evaluation.stderr"; then
                cat "$out/$evaluation.stderr" >&2
                echo "Native read-only evaluation failed: $evaluation" >&2
                exit 1
              fi
            done
            ${pkgs.diffutils}/bin/cmp "$out/first.json" "$out/second.json"
            # Replay retains the immutable descriptor, authenticated publication
            # companions, and source roots without granting execution authority.
            if ! ${pkgs.jq}/bin/jq -e \
              --slurpfile fixture ${fixture}/fixture.json \
              '([$fixture[0].library, $fixture[0].configuration]
                + $fixture[0].document.inputs
                + ($fixture[0].publications | map(.envelope | sub("/[^/]+$"; "")))
                | unique) as $expected
                | (del(.inputs) == ($fixture[0].document | del(.inputs)))
                  and ((.inputs - $expected) as $descriptors
                    | ($descriptors | length) == 1
                      and ($descriptors[0] | endswith("-evaluation-input.json")))
                  and (($expected - .inputs | length) == 0)' \
              "$out/first.json" >/dev/null; then
              echo "Native deployment differs from the admitted fixture" >&2
              ${pkgs.jq}/bin/jq '{schema, scope, inputs}' "$out/first.json" >&2
              exit 1
            fi
            descriptor_path="$(${pkgs.jq}/bin/jq -r \
              --slurpfile fixture ${fixture}/fixture.json \
              '.inputs - ([$fixture[0].library, $fixture[0].configuration]
                + $fixture[0].document.inputs
                + ($fixture[0].publications | map(.envelope | sub("/[^/]+$"; "")))
                | unique) | .[0]' "$out/first.json")"
            cp "$evaluation_store_root$descriptor_path" "$out/evaluation-input.json"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
