##! lib/build/oci/metadata-layer.nix -- deterministic authored root metadata.
##!
##! Metadata is intentionally described as typed directories, text files, and
##! symlinks.  There is no arbitrary source-tree import: internal callers may
##! copy one explicitly named regular file from the Nix store (for generated
##! registration/init data), but the public container schema does not expose
##! that escape hatch.  Layer ABI v1 is root-owned; a future ownership model
##! must use a new ABI.
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
  directories ? [],
  files ? [],
  symlinks ? [],
  storeLayers ? [],
  pname ? "aos-oci-root-metadata-layer",
  layerName ? pname,
}: let
  normalizeOwner = context: entry:
    if (entry.uid or 0) != 0 || (entry.gid or 0) != 0
    then common.fail "${context} requests non-root ownership, which layer ABI v1 forbids"
    else entry;
  normalizedDirectories =
    lib.imap (
      index: raw: let
        entry = normalizeOwner "directories[${toString index}]" raw;
      in {
        kind = "directory";
        path = common.validatePath "directories[${toString index}].path" entry.path;
        mode = common.validateMode "directories[${toString index}].mode" (entry.mode or "0755");
      }
    )
    directories;
  normalizedFiles =
    lib.imap (
      index: raw: let
        entry = normalizeOwner "files[${toString index}]" raw;
        hasText = entry ? text;
        hasSource = entry ? source;
        text =
          if hasText
          then common.validateText "files[${toString index}].text" entry.text
          else null;
        source =
          if hasSource
          then common.validateStoreFile "files[${toString index}].source" entry.source
          else null;
      in {
        kind = "file";
        path = common.validatePath "files[${toString index}].path" entry.path;
        mode = common.validateMode "files[${toString index}].mode" (entry.mode or "0644");
        inherit text source;
        validPayload =
          if hasText == hasSource
          then common.fail "files[${toString index}] must set exactly one of text or source"
          else true;
      }
    )
    files;
  normalizedSymlinks =
    lib.imap (
      index: entry: {
        kind = "symlink";
        path = common.validatePath "symlinks[${toString index}].path" entry.path;
        target = common.validateTarget "symlinks[${toString index}].target" entry.target;
        requireExecutable = let
          value = entry.requireExecutable or false;
        in
          if builtins.isBool value
          then value
          else common.fail "symlinks[${toString index}].requireExecutable must be a boolean";
      }
    )
    symlinks;
  entries = common.validateMetadataEntries (normalizedDirectories ++ normalizedFiles ++ normalizedSymlinks);
  validated =
    if !builtins.isList directories || !builtins.isList files || !builtins.isList symlinks
    then common.fail "directories, files, and symlinks must be lists"
    else if builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*$" layerName == null
    then common.fail "layerName is invalid"
    else if
      !lib.all
      (layer: builtins.isAttrs layer && (layer.passthru.ociClosureLayer or false))
      storeLayers
    then common.fail "storeLayers must contain only mkClosureLayer outputs"
    else builtins.deepSeq entries true;

  parentScripts = lib.concatMapStringsSep "\n" (entry: ''
    mkdir -p "$(dirname ${lib.escapeShellArg "root${entry.path}"})"
  '') (normalizedFiles ++ normalizedSymlinks);
  directoryScripts =
    lib.concatMapStringsSep "\n" (entry: ''
      mkdir -p ${lib.escapeShellArg "root${entry.path}"}
    '')
    normalizedDirectories;
  directoryModeScripts =
    lib.concatMapStringsSep "\n" (entry: ''
      chmod ${entry.mode} ${lib.escapeShellArg "root${entry.path}"}
    '')
    normalizedDirectories;
  fileScripts = lib.concatMapStringsSep "\n" (indexed: let
    entry = indexed.value;
  in
    builtins.deepSeq entry.validPayload ''
      metadata_destination=${lib.escapeShellArg "root${entry.path}"}
      if [ -e "$metadata_destination" ] || [ -L "$metadata_destination" ]; then
        echo "metadata path collision: ${entry.path}" >&2
        exit 1
      fi
      ${
        if entry.source != null
        then ''
          metadata_source=${lib.escapeShellArg entry.source}
          if [ ! -f "$metadata_source" ] || [ -L "$metadata_source" ]; then
            echo "metadata source is not a regular non-symlink file: $metadata_source" >&2
            exit 1
          fi
          cp --reflink=auto "$metadata_source" "$metadata_destination"
        ''
        else ''
          jq -j ${lib.escapeShellArg ".metadataSpec.files[${toString indexed.index}].text"} \
            "$NIX_ATTRS_JSON_FILE" > "$metadata_destination"
        ''
      }
      chmod ${entry.mode} "$metadata_destination"
    '') (lib.imap (index: value: {inherit index value;}) normalizedFiles);
  symlinkScripts =
    lib.concatMapStringsSep "\n" (entry: ''
      metadata_destination=${lib.escapeShellArg "root${entry.path}"}
      if [ -e "$metadata_destination" ] || [ -L "$metadata_destination" ]; then
        echo "metadata path collision: ${entry.path}" >&2
        exit 1
      fi
      metadata_target=${lib.escapeShellArg entry.target}
      case "$metadata_target" in
        /nix/store/*)
          validate_store_symlink_target \
            realized-store-paths.allowed \
            "$metadata_target" \
            ${
        if entry.requireExecutable
        then "1"
        else "0"
      }
          ;;
      esac
      ln -s ${lib.escapeShellArg entry.target} "$metadata_destination"
    '')
    normalizedSymlinks;
  storeLayerArguments =
    lib.concatMapStringsSep " "
    (layer: lib.escapeShellArg (builtins.toString layer))
    storeLayers;
  metadataSpec = {
    schema = "aos.container.root-metadata/v1";
    inherit layerName;
    directories = map (entry: {inherit (entry) path mode;}) normalizedDirectories;
    files = map (entry: {inherit (entry) path mode text source;}) normalizedFiles;
    symlinks = map (entry: {inherit (entry) path target requireExecutable;}) normalizedSymlinks;
  };
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils findutils gzip jq tar] ++ storeLayers;

    outputChecks.out = {};
    inherit metadataSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export LC_ALL=C
          export SOURCE_DATE_EPOCH=1
          umask 022

          ${common.archiveScript}
          ${common.jsonScript}
          ${common.realizedStorePolicyScript}
          verify_archive_tools

          validate_disjoint_layer_inventories \
            realized-store-paths \
            ${storeLayerArguments}

          mkdir -p root "$out"
          ${parentScripts}
          ${directoryScripts}

          # mkdir-created parents are part of the authored layer contract too.
          # Give every implicit directory a deterministic mode before applying
          # explicit directory overrides.
          find root -type d -exec chmod 0755 {} +
          ${directoryModeScripts}
          ${fileScripts}
          ${symlinkScripts}

          make_gzip_layer root members layer.tar "$out/blob"
          diffid_hex=$(sha256sum layer.tar | cut -d ' ' -f 1)
          diffid_size=$(stat -c %s layer.tar)
          blob_hex=$(sha256sum "$out/blob" | cut -d ' ' -f 1)
          blob_size=$(stat -c %s "$out/blob")

          printf 'sha256:%s' "$diffid_hex" > "$out/diffid"
          printf '%s' "$diffid_size" > "$out/uncompressed-size"
          printf 'sha256:%s' "$blob_hex" > "$out/blob-digest"
          printf '%s' "$blob_size" > "$out/blob-size"

          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.layerMediaType} \
            --arg digest "sha256:$blob_hex" \
            --argjson size "$blob_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > descriptor.pretty.json
          write_compact_json descriptor.pretty.json "$out/descriptor.json"

          jq '.metadataSpec' "$NIX_ATTRS_JSON_FILE" > metadata-spec.json
          jq -S \
            --arg digest "sha256:$blob_hex" \
            --arg diffid "sha256:$diffid_hex" \
            --argjson compressedSize "$blob_size" \
            --argjson uncompressedSize "$diffid_size" \
            '. + {
              digest: $digest,
              diffID: $diffid,
              compressedSize: $compressedSize,
              uncompressedSize: $uncompressedSize
            }
            | .files |= map(del(.text, .source))
          ' metadata-spec.json > metadata.pretty.json
          write_compact_json metadata.pretty.json "$out/metadata.json"

          rm -f layer.tar descriptor.pretty.json metadata.pretty.json metadata-spec.json
        '';
      }
    ];

    passthru = {
      ociLayer = true;
      inherit layerName;
      mediaType = common.layerMediaType;
      metadataEntries = entries;
    };

    meta.description = "Deterministic authored OCI root metadata layer ${layerName}";
  })
