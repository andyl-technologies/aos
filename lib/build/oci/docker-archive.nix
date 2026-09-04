##! lib/build/oci/docker-archive.nix -- deterministic Docker load archive.
##!
##! Converts one platform image without invoking Docker, Podman, or BuildKit.
##! Layer tar streams and config bytes are taken from the already-verified OCI
##! image; the adapter only supplies Docker's legacy `manifest.json` envelope.
{
  lib,
  mkDerivation,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
  common,
}: {
  image,
  references,
  pname ? "aos-docker-archive",
}: let
  checkedReferences =
    map
    (common.validateTaggedReference "Docker archive reference")
    (common.validateStringList "references" references);
  validated =
    if !(builtins.isAttrs image && (image.passthru.ociImage or false))
    then common.fail "image must be produced by mkImageLayout"
    else if checkedReferences == []
    then common.fail "a Docker archive requires at least one repository tag"
    else true;
  dockerSpec = {inherit checkedReferences;};
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname dockerSpec;
    version = "1";
    src = null;
    buildDeps = [coreutils findutils gzip jq tar image];
    outputChecks.out = {};
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "convert";
        script = ''
          set -eu
          export LC_ALL=C
          export SOURCE_DATE_EPOCH=1
          umask 022
          ${common.archiveScript}
          ${common.jsonScript}
          verify_archive_tools

          mkdir -p root "$out"
          jq -e '
            (.layers | type == "array")
            and .config.mediaType == ${builtins.toJSON common.configMediaType}
          ' ${image}/manifest.json >/dev/null
          jq -e '
            .rootfs.type == "layers"
            and (.rootfs.diff_ids | type == "array")
          ' ${image}/config.json >/dev/null
          layer_count=$(jq '.layers | length' ${image}/manifest.json)
          diffid_count=$(jq '.rootfs.diff_ids | length' ${image}/config.json)
          test "$layer_count" -eq "$diffid_count" \
            || { echo "Docker conversion found a layer/DiffID count mismatch" >&2; exit 1; }

          config_hex=$(sha256sum ${image}/config.json | cut -d ' ' -f 1)
          cp --reflink=auto ${image}/config.json "root/$config_hex.json"
          : > layer-paths.jsonl
          jq -r --slurpfile config ${image}/config.json '
            range(0; (.layers | length)) as $index
            | [.layers[$index].digest, $config[0].rootfs.diff_ids[$index]]
            | @tsv
          ' ${image}/manifest.json | while IFS="$(printf '\t')" read -r blob_digest diffid; do
            blob_hex=''${blob_digest#sha256:}
            diffid_hex=''${diffid#sha256:}
            source_blob=${image}/layout/blobs/sha256/$blob_hex
            test -f "$source_blob"
            gzip -t "$source_blob"
            mkdir "root/$diffid_hex"
            gzip -dc "$source_blob" > "root/$diffid_hex/layer.tar"
            actual_diffid=$(sha256sum "root/$diffid_hex/layer.tar" | cut -d ' ' -f 1)
            test "$actual_diffid" = "$diffid_hex" \
              || { echo "Docker layer DiffID mismatch: $source_blob" >&2; exit 1; }
            jq -c -n --arg path "$diffid_hex/layer.tar" '$path' >> layer-paths.jsonl
          done

          jq -s '.' layer-paths.jsonl > layer-paths.pretty.json
          write_compact_json layer-paths.pretty.json layer-paths.json
          jq '.dockerSpec' "$NIX_ATTRS_JSON_FILE" > docker-spec.json
          jq -S -n \
            --arg config "$config_hex.json" \
            --slurpfile layers layer-paths.json \
            --slurpfile spec docker-spec.json '
              [{Config: $config, RepoTags: $spec[0].checkedReferences, Layers: $layers[0]}]
            ' > manifest.pretty.json
          write_compact_json manifest.pretty.json root/manifest.json
          cp --reflink=auto root/manifest.json "$out/manifest.json"

          make_deterministic_tar root archive-members "$out/image.docker.tar"
          rm -f layer-paths.json layer-paths.jsonl layer-paths.pretty.json \
            docker-spec.json manifest.pretty.json archive-members
        '';
      }
    ];

    passthru.dockerArchive = true;
    meta.description = "Deterministic Docker load archive converted from an AOS OCI image";
  })
