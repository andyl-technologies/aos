# tests/build/structured-attrs-scrub.nix - Reference scrubbing under structured attrs
{pkgs}: let
  mkReference = name:
    pkgs.mkDerivation {
      pname = "structured-attrs-scrub-${name}";
      version = "0";
      src = null;

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            echo reference > "$out/value"
          '';
        }
      ];
    };

  runtimeReferences = [
    (mkReference "runtime-one")
    (mkReference "runtime-two")
  ];
  propagatedReferences = [
    (mkReference "propagated-one")
    (mkReference "propagated-two")
  ];
  customKeepReferences = [
    (mkReference "custom-one")
    (mkReference "custom-two")
  ];
  unwantedReferences = [
    (mkReference "unwanted-one")
    (mkReference "unwanted-two")
  ];
  retainedReferences =
    runtimeReferences
    ++ propagatedReferences
    ++ customKeepReferences;

  scrubbedReference = reference:
    builtins.replaceStrings
    [(builtins.substring 11 32 (builtins.toString reference))]
    ["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]
    (builtins.toString reference);

  referenceManifest = builtins.concatStringsSep "\n" (
    builtins.map builtins.toString (retainedReferences ++ unwantedReferences)
  );

  mkPayload = {
    name,
    structured,
  }:
    pkgs.mkDerivation {
      pname = "structured-attrs-scrub-${name}-payload";
      version = "0";
      src = null;
      outputs = ["out" "secondary"];

      buildDeps = unwantedReferences;
      runtimeDeps = runtimeReferences;
      propagatedDeps = propagatedReferences;
      nukeRefsKeep = customKeepReferences;
      outputChecks =
        if structured
        then {
          out.disallowedRequisites = unwantedReferences;
          secondary.disallowedRequisites = unwantedReferences;
        }
        else null;

      phases = [
        {
          name = "install";
          script = ''
            for output in "$out" "$secondary"; do
              mkdir -p "$output/lib"
              cat > "$output/lib/references.la" <<'REFERENCES'
            ${referenceManifest}
            REFERENCES
            done
          '';
        }
      ];
    };

  scalarPayload = mkPayload {
    name = "scalar";
    structured = false;
  };
  structuredPayload = mkPayload {
    name = "structured";
    structured = true;
  };

  retainedChecks = builtins.concatStringsSep "\n" (
    builtins.map (reference: ''
        check_present "$manifest" "${reference}"
      '')
    retainedReferences
  );
  unwantedChecks = builtins.concatStringsSep "\n" (
    builtins.map (reference: ''
        check_absent "$manifest" "${reference}"
        check_present "$manifest" "${scrubbedReference reference}"
      '')
    unwantedReferences
  );
in
  pkgs.mkDerivation {
    pname = "structured-attrs-scrub-check";
    version = "0";
    src = null;
    buildDeps = [
      scalarPayload
      scalarPayload.secondary
      structuredPayload
      structuredPayload.secondary
    ];

    phases = [
      {
        name = "check";
        script = ''
          failures=0

          check_present() {
            manifest=$1
            reference=$2
            if ! grep -Fxq "$reference" "$manifest"; then
              echo "missing retained reference in $manifest: $reference" >&2
              failures=$((failures + 1))
            fi
          }

          check_absent() {
            manifest=$1
            reference=$2
            if grep -Fq "$reference" "$manifest"; then
              echo "unscrubbed build-only reference in $manifest: $reference" >&2
              failures=$((failures + 1))
            fi
          }

          check_payload() {
            primary=$1
            secondary=$2

            for output in "$primary" "$secondary"; do
              manifest="$output/lib/references.la"
              test -f "$manifest"
          ${retainedChecks}
          ${unwantedChecks}
            done
          }

          check_payload ${scalarPayload} ${scalarPayload.secondary}
          check_payload ${structuredPayload} ${structuredPayload.secondary}

          if [ "$failures" -ne 0 ]; then
            echo "structured attrs scrub check found $failures errors" >&2
            exit 1
          fi

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
