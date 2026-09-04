##! lib/build/oci/multi-platform-index.nix -- multi-platform OCI indexes.
##!
##! This builder composes already-built platform manifests without unpacking a
##! layer.  Platform descriptors are sorted by canonical platform identity, and
##! every referenced blob is copied into the resulting layout with digest and
##! collision verification.
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
  images,
  annotations ? {},
  referenceName ? null,
  pname ? "aos-oci-multi-platform-image",
}: let
  imagePaths = map builtins.toString images;
  validateAnnotations = values: let
    checked =
      if builtins.isAttrs values
      then
        lib.mapAttrs (
          name: value:
            if builtins.match "^[A-Za-z0-9][A-Za-z0-9._/-]*$" name == null
            then common.fail "annotations contains invalid key ${builtins.toJSON name}"
            else if builtins.stringLength name > 1024
            then common.fail "annotation key exceeds 1 KiB"
            else if !builtins.isString value || builtins.stringLength value > 4096
            then common.fail "annotation ${name} exceeds 4 KiB or is not a string"
            else value
        )
        values
      else common.fail "annotations must be an attribute set";
    total =
      builtins.foldl' (
        size: name: size + builtins.stringLength name + builtins.stringLength checked.${name}
      )
      0 (builtins.attrNames checked);
  in
    if total > 65536
    then common.fail "annotations exceeds the 64 KiB aggregate limit"
    else checked;
  checkedAnnotations = validateAnnotations annotations;
  referenceAnnotations =
    if referenceName == null
    then {}
    else {
      "org.opencontainers.image.ref.name" =
        common.validateTaggedReference "referenceName" referenceName;
    };
  coordinatedAnnotations =
    if
      referenceName
      != null
      && checkedAnnotations ? "org.opencontainers.image.ref.name"
      && checkedAnnotations."org.opencontainers.image.ref.name"
      != referenceAnnotations."org.opencontainers.image.ref.name"
    then
      common.fail
      "annotations org.opencontainers.image.ref.name conflicts with referenceName"
    else checkedAnnotations // referenceAnnotations;
  validated =
    if !builtins.isList images
    then common.fail "images must be a list"
    else if images == []
    then common.fail "a multi-platform index requires at least one image"
    else if builtins.length images > 256
    then common.fail "a multi-platform index may contain at most 256 platforms"
    else if builtins.length imagePaths != builtins.length (lib.unique imagePaths)
    then common.fail "images contains the same derivation more than once"
    else if !lib.all (image: builtins.isAttrs image && (image.passthru.ociImage or false)) images
    then common.fail "every input must be produced by mkImageLayout"
    else builtins.deepSeq coordinatedAnnotations true;
  indexSpec = {
    annotations = coordinatedAnnotations;
    descriptorAnnotations = coordinatedAnnotations;
  };
  addImageScripts =
    lib.concatMapStringsSep "\n" (image: ''
      add_image ${lib.escapeShellArg (builtins.toString image)}
    '')
    images;
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils findutils gzip jq tar] ++ images;

    outputChecks.out = {};
    inherit indexSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "assemble";
        script = ''
          set -eu
          export LC_ALL=C
          export SOURCE_DATE_EPOCH=1
          umask 022

          ${common.archiveScript}
          ${common.jsonScript}
          verify_archive_tools

          mkdir -p "$out/layout/blobs/sha256"
          jq '.indexSpec' "$NIX_ATTRS_JSON_FILE" > index-spec.input.json
          : > manifests.jsonl

          add_image() {
            image_path="$1"
            test -d "$image_path/layout/blobs/sha256"
            test -f "$image_path/manifest-descriptor.json"
            jq -e '
              type == "object"
              and .mediaType == ${builtins.toJSON common.manifestMediaType}
              and (.digest | test("^sha256:[0-9a-f]{64}$"))
              and (.size | type == "number" and . >= 0 and floor == .)
              and (.platform.os == "linux")
              and (.platform.architecture == "amd64" or .platform.architecture == "arm64")
            ' "$image_path/manifest-descriptor.json" >/dev/null

            manifest_digest=$(jq -r .digest "$image_path/manifest-descriptor.json")
            manifest_hex=''${manifest_digest#sha256:}
            manifest_size=$(jq -r .size "$image_path/manifest-descriptor.json")
            actual_hex=$(sha256sum "$image_path/layout/blobs/sha256/$manifest_hex" | cut -d ' ' -f 1)
            actual_size=$(stat -c %s "$image_path/layout/blobs/sha256/$manifest_hex")
            if [ "$actual_hex" != "$manifest_hex" ] || [ "$actual_size" -ne "$manifest_size" ]; then
              echo "platform manifest descriptor does not match its blob: $image_path" >&2
              exit 1
            fi

            for source_blob in "$image_path/layout/blobs/sha256/"*; do
              test -f "$source_blob"
              blob_name=''${source_blob##*/}
              case "$blob_name" in
                ????????????????????????????????????????????????????????????????) ;;
                *)
                  echo "invalid blob filename: $blob_name" >&2
                  exit 1
                  ;;
              esac
              source_hex=$(sha256sum "$source_blob" | cut -d ' ' -f 1)
              if [ "$source_hex" != "$blob_name" ]; then
                echo "input layout contains a misnamed blob: $source_blob" >&2
                exit 1
              fi
              destination="$out/layout/blobs/sha256/$blob_name"
              if [ -e "$destination" ]; then
                cmp "$source_blob" "$destination"
              else
                cp --reflink=auto "$source_blob" "$destination"
              fi
            done

            cat "$image_path/manifest-descriptor.json" >> manifests.jsonl
            printf '\n' >> manifests.jsonl
          }

          ${addImageScripts}

          jq -s -e '
            sort_by(.platform.os, .platform.architecture, (.platform.variant // ""))
            | group_by([.platform.os, .platform.architecture, (.platform.variant // "")])
            | all(length == 1)
          ' manifests.jsonl >/dev/null \
            || { echo "multi-platform index contains a duplicate platform" >&2; exit 1; }
          jq -S -s '
            sort_by(.platform.os, .platform.architecture, (.platform.variant // ""), .digest)
          ' manifests.jsonl > manifests.pretty.json
          write_compact_json manifests.pretty.json manifests.json

          # This is the publishable multi-platform index object.
          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.indexMediaType} \
            --slurpfile manifests manifests.json \
            --slurpfile spec index-spec.input.json '
              {
                schemaVersion: 2,
                mediaType: $mediaType,
                manifests: $manifests[0],
                annotations: $spec[0].annotations
              }
            ' > image-index.pretty.json
          write_compact_json image-index.pretty.json "$out/image-index.json"

          index_hex=$(sha256sum "$out/image-index.json" | cut -d ' ' -f 1)
          index_size=$(stat -c %s "$out/image-index.json")
          index_blob="$out/layout/blobs/sha256/$index_hex"
          if [ -e "$index_blob" ]; then
            # A one-platform composition can produce the exact index object
            # already present in its input layout. Treat that as verified blob
            # reuse instead of attempting to overwrite a read-only copied blob.
            cmp "$out/image-index.json" "$index_blob" \
              || { echo "existing index blob does not match its digest" >&2; exit 1; }
          else
            cp --reflink=auto "$out/image-index.json" "$index_blob"
          fi
          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.indexMediaType} \
            --arg digest "sha256:$index_hex" \
            --argjson size "$index_size" \
            --slurpfile spec index-spec.input.json '
              {mediaType: $mediaType, digest: $digest, size: $size}
              + (if ($spec[0].descriptorAnnotations | length) == 0
                 then {}
                 else {annotations: $spec[0].descriptorAnnotations}
                 end)
            ' > index-descriptor.pretty.json
          write_compact_json index-descriptor.pretty.json "$out/index-descriptor.json"

          # OCI layout index.json is the entry-point catalog.  It points at the
          # multi-platform image index blob rather than duplicating its children.
          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.indexMediaType} \
            --slurpfile descriptor "$out/index-descriptor.json" '
              {schemaVersion: 2, mediaType: $mediaType, manifests: [$descriptor[0]]}
            ' > layout-index.pretty.json
          write_compact_json layout-index.pretty.json "$out/layout/index.json"
          printf '%s' '{"imageLayoutVersion":"${common.layoutVersion}"}' > "$out/layout/oci-layout"

          make_deterministic_tar "$out/layout" archive-members "$out/image.oci.tar"
          rm -f *.pretty.json manifests.json manifests.jsonl index-spec.input.json archive-members
        '';
      }
    ];

    passthru = {
      ociImageIndex = true;
      mediaType = common.indexMediaType;
    };

    meta.description = "Self-contained deterministic multi-platform OCI image index";
  })
