##! runtime-closure-audit — fail-closed image payload policy
##!
##! Audits the complete set of store roots copied into an image. This is
##! intentionally separate from filesystem compression and partition sizing:
##! a compact build-time dependency is still an invalid runtime payload.
{
  pkgs,
  lib,
  name,
  roots,
  maxClosureMiB,
  maxDevelopmentPayloadMiB,
  allowTestArtifacts ? false,
  testArtifactRoots ? [],
}: let
  mib = 1048576;
  checkedTestArtifactRoots = assert allowTestArtifacts || testArtifactRoots == []; testArtifactRoots;
in
  pkgs.mkDerivation {
    pname = "aos-${name}-runtime-closure-audit";
    version = "1";
    src = null;

    outputChecks = {};
    exportReferencesGraph = {
      runtime = roots;
      testArtifacts = checkedTestArtifactRoots;
    };
    buildDeps = [pkgs.coreutils pkgs.jq];
    dontStrip = true;
    dontNukeRefs = true;

    MAX_CLOSURE_BYTES = toString (maxClosureMiB * mib);
    MAX_DEVELOPMENT_PAYLOAD_BYTES = toString (maxDevelopmentPayloadMiB * mib);
    ALLOW_TEST_ARTIFACTS =
      if allowTestArtifacts
      then "1"
      else "0";

    phases = [
      {
        name = "audit";
        script = ''
          set -eu
          mkdir -p "$out"

          is_forbidden_runtime_name() {
            case "$1" in
              *-vendor-*|*-cargo-artifacts-*|*-cargo-deps-*|*-cargo-dummy-source*|*.bpf.c|\
              rust-[0-9]*|cargo-[0-9]*|gcc-[0-9]*|binutils-[0-9]*|cmake-*|meson-*|ninja-*|\
              pkg-config-*|gnumake-*|autoconf-*|automake-*|bison-*|flex-*|gperf-*|python3-*)
                return 0
                ;;
            esac

            if [ "$ALLOW_TEST_ARTIFACTS" != 1 ]; then
              case "$1" in
                aos-test-agent*|secure-boot-test-keys*) return 0 ;;
              esac
            fi
            return 1
          }

          # Keep representative classifier assertions beside the policy so a
          # pattern edit cannot silently turn the audit into a no-op.
          is_forbidden_runtime_name aos-vendor-0.1.0
          is_forbidden_runtime_name aos-ebpf-net-policy.bpf.c
          is_forbidden_runtime_name python3-3.13.1
          if is_forbidden_runtime_name gcc-libs-14.2.0; then
            echo "runtime classifier rejected the valid gcc-libs package" >&2
            exit 1
          fi

          closure_bytes=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
          if [ "$closure_bytes" -gt "$MAX_CLOSURE_BYTES" ]; then
            echo "runtime closure is $closure_bytes bytes; image contract permits at most $MAX_CLOSURE_BYTES bytes" >&2
            exit 1
          fi

          : > forbidden-paths
          jq -r '.testArtifacts[].path' "$NIX_ATTRS_JSON_FILE" > allowed-test-paths
          jq -r '.runtime[].path' "$NIX_ATTRS_JSON_FILE" | while IFS= read -r path; do
            store_name=''${path#/nix/store/}
            store_name=''${store_name#*-}
            if is_forbidden_runtime_name "$store_name" \
              && ! grep -Fxq "$path" allowed-test-paths; then
              printf '%s\n' "$path" >> forbidden-paths
            fi
          done
          if [ -s forbidden-paths ]; then
            echo "image runtime closure contains forbidden build, source, or test artifacts:" >&2
            sort -u forbidden-paths >&2
            exit 1
          fi

          # Until every upstream library has clean multi-output packaging,
          # ratchet the remaining development payload independently from the
          # total closure. This prevents headers/static archives from growing
          # unnoticed and gives output-splitting work a monotonic target.
          : > development-files
          jq -r '.runtime[].path' "$NIX_ATTRS_JSON_FILE" | while IFS= read -r path; do
            find "$path" -type f \
              \( -path '*/include/*' -o -name '*.a' -o -name '*.la' \
                 -o -path '*/pkgconfig/*' -o -path '*/cmake/*' \
                 -o -path '*/aclocal/*' \) \
              -printf '%s\t%p\n' >> development-files
          done
          development_payload_bytes=$(awk '{ total += $1 } END { print total + 0 }' development-files)
          if [ "$development_payload_bytes" -gt "$MAX_DEVELOPMENT_PAYLOAD_BYTES" ]; then
            echo "development payload is $development_payload_bytes bytes; image contract permits at most $MAX_DEVELOPMENT_PAYLOAD_BYTES bytes" >&2
            sort -nr development-files | head -50 >&2
            exit 1
          fi

          jq -S -n \
            --arg name ${lib.escapeShellArg name} \
            --argjson closureBytes "$closure_bytes" \
            --argjson developmentPayloadBytes "$development_payload_bytes" \
            --argjson maxClosureMiB ${toString maxClosureMiB} \
            --argjson maxDevelopmentPayloadMiB ${toString maxDevelopmentPayloadMiB} \
            '{
              schema: "aos.runtime-closure-audit/v1",
              name: $name,
              actual: {
                closureBytes: $closureBytes,
                developmentPayloadBytes: $developmentPayloadBytes
              },
              maximumMiB: {
                closure: $maxClosureMiB,
                developmentPayload: $maxDevelopmentPayloadMiB
              }
            }' > "$out/report.json"
          sort -nr development-files > "$out/development-files.tsv"
        '';
      }
    ];

    meta.description = "Runtime closure hygiene audit for the ${name} image";
  }
