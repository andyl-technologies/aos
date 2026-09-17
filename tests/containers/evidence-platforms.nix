##! Checks exact closure-layer bindings for single- and multi-platform evidence.
{pkgs}: let
  buildPackages = pkgs.buildPackages or pkgs;
in
  buildPackages.mkDerivation {
    pname = "aos-container-evidence-platform-bindings";
    version = "1";
    src = null;
    buildDeps = [buildPackages.coreutils buildPackages.diffutils buildPackages.jq];
    outputChecks.out = {};

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          fixture_root=$PWD
          mkdir -p layout/blobs/sha256

          write_layer() {
            label=$1
            number=$2
            digest=$(printf '%064d' "$number")
            jq -n --arg digest "sha256:$digest" --argjson size "$number" \
              '{mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: $digest, size: $size}' \
              > "$label.json"
          }

          write_manifest() {
            label=$1
            architecture=$2
            layers=$3
            jq -n --slurpfile layers "$layers" '{
              schemaVersion: 2,
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              layers: $layers[0]
            }' > "$label.manifest.json"
            digest=$(sha256sum "$label.manifest.json" | cut -d ' ' -f 1)
            size=$(stat -c %s "$label.manifest.json")
            cp "$label.manifest.json" "layout/blobs/sha256/$digest"
            jq -n --arg digest "sha256:$digest" --argjson size "$size" \
              --arg architecture "$architecture" '{
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                digest: $digest,
                size: $size,
                platform: {os: "linux", architecture: $architecture}
              }' > "$label.descriptor.json"
          }

          write_index() {
            destination=$1
            shift
            jq -s '{
              schemaVersion: 2,
              mediaType: "application/vnd.oci.image.index.v1+json",
              manifests: .
            }' "$@" > "$destination"
          }

          check_binding() {
            label=$1
            expected=$2
            index=$3
            layers=$4
            mkdir "$label"
            actual=rejected
            if (
              cd "$label"
              "$CONFIG_SHELL" ${../../lib/build/oci/evidence-platforms.sh} \
                "$fixture_root/$index" "$fixture_root/layout" "$fixture_root/$layers"
            ) > "$label.log" 2>&1; then
              actual=accepted
            fi
            if [ "$actual" != "$expected" ]; then
              cat "$label.log" >&2
              echo "$label: expected $expected, got $actual" >&2
              exit 1
            fi
          }

          write_layer amd 11
          write_layer arm 12
          write_layer metadata 13
          write_layer unused 14
          jq -s . amd.json metadata.json > amd-layers.json
          jq -s . arm.json metadata.json > arm-layers.json
          write_manifest amd amd64 amd-layers.json
          write_manifest arm arm64 arm-layers.json
          write_index single-index.json amd.descriptor.json
          write_index multi-index.json amd.descriptor.json arm.descriptor.json
          jq -s . amd.json > single-closure.json
          jq -s . arm.json amd.json > multi-closure.json

          check_binding single accepted single-index.json single-closure.json
          check_binding multi-reversed-inputs accepted multi-index.json multi-closure.json

          jq -s . arm.json amd.json unused.json > extra-closure.json
          check_binding unattached-layer rejected multi-index.json extra-closure.json
          check_binding missing-platform-layers rejected multi-index.json single-closure.json
          jq -s . amd.json amd.json > duplicate-closure.json
          check_binding repeated-layer rejected single-index.json duplicate-closure.json

          jq -s . amd.json amd.json metadata.json > repeated-platform-layers.json
          write_manifest repeated-layer amd64 repeated-platform-layers.json
          write_index repeated-layer-index.json repeated-layer.descriptor.json
          check_binding repeated-platform-layer rejected repeated-layer-index.json single-closure.json

          jq -s . metadata.json amd.json > nonprefix-layers.json
          write_manifest nonprefix amd64 nonprefix-layers.json
          write_index nonprefix-index.json nonprefix.descriptor.json
          check_binding nonprefix rejected nonprefix-index.json single-closure.json

          jq '.size += 1' amd.json > wrong-size-layer.json
          jq -s . wrong-size-layer.json metadata.json > wrong-size-layers.json
          write_manifest wrong-size amd64 wrong-size-layers.json
          write_index wrong-size-index.json wrong-size.descriptor.json
          check_binding conflicting-layer-size rejected wrong-size-index.json single-closure.json

          jq '.manifests[1].platform.architecture = "amd64"' multi-index.json > duplicate-platform-index.json
          check_binding repeated-platform rejected duplicate-platform-index.json multi-closure.json
          jq '.manifests[0].platform.variant = 8' single-index.json > invalid-variant-index.json
          check_binding invalid-platform-variant rejected invalid-variant-index.json single-closure.json
          jq '.manifests[0].size += 1' single-index.json > wrong-manifest-size-index.json
          check_binding conflicting-manifest-size rejected wrong-manifest-size-index.json single-closure.json

          digest=$(jq -r '.digest | sub("^sha256:"; "")' amd.descriptor.json)
          tr 'a' 'b' < amd.manifest.json > "layout/blobs/sha256/$digest"
          check_binding conflicting-manifest-digest rejected single-index.json single-closure.json
          cp amd.manifest.json "layout/blobs/sha256/$digest"
          printf ' ' >> "layout/blobs/sha256/$digest"
          check_binding altered-manifest rejected single-index.json single-closure.json

          mkdir -p "$out"
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  }
