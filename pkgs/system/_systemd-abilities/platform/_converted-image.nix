##! Retains canonical provider artifacts beside one converted delivery encoding.
{
  baseImage,
  config,
  lib,
  metadataFilename,
  pkgs,
  rawImage,
  targetPlatform,
}:
pkgs.mkDerivation {
  pname = "aos-image-${config.aos.system.name}-${baseImage.IMAGE_FORMAT or "converted"}-systemd-artifacts";
  version = config.aos.system.version;
  src = null;
  buildDeps = [pkgs.coreutils pkgs.jq pkgs.openssl];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        # Additional artifacts and platform metadata belong to the new output.
        cp -a --no-preserve=mode ${baseImage}/. "$out/"

        # Copy exact paths authored by the canonical provider serializer.
        # Delivery conversion never rewrites these authenticated facts.
        jq -er '[.efi.normal_a, .efi.normal_b] | .[]
          | (.artifact.path, .measurement.path?, .measurement_signature.path?)
          | select(. != null)' "$out/${metadataFilename}" > normal-artifacts
        jq -er '.efi.bootloader.path' "$out/${metadataFilename}" >> normal-artifacts
        while IFS= read -r component; do
          case "$component" in
            ""|.|..|*/*) echo "unsafe canonical provider artifact path" >&2; exit 1 ;;
          esac
          cp "${rawImage}/$component" "$out/$component"
        done < normal-artifacts

        for component in root.img uki-a.efi uki-b.efi; do
          cp "${rawImage}/$component" "$out/$component"
        done
        ${lib.optionalString config.aos.security.verity.enable ''
          for component in root.verity root.roothash root.roothash.p7s; do
            cp "${rawImage}/$component" "$out/$component"
          done
        ''}

        ${lib.optionalString config.aos.boot.recovery.enable ''
          for component in \
            recovery-a.efi recovery-b.efi \
            recovery-a.conf recovery-b.conf; do
            cp "${rawImage}/$component" "$out/$component"
          done''}

        ${lib.optionalString config.aos.boot.recovery.enable ''
          component() {
            id=$1
            path=$2
            size=$(stat -c %s "$out/$path")
            digest=$(sha256sum "$out/$path" | cut -d ' ' -f1)
            jq -n \
              --arg id "$id" --arg path "$path" \
              --argjson byteSize "$size" --arg sha256 "$digest" \
              '{id: $id, path: $path, byte_size: $byteSize, sha256: $sha256}'
          }
          components=$(
            {
              component root-image root.img
              component root-verity root.verity
              component root-hash root.roothash
              component normal-uki-a "$(jq -er '.efi.normal_a.artifact.path' "$out/${metadataFilename}")"
              component normal-uki-b "$(jq -er '.efi.normal_b.artifact.path' "$out/${metadataFilename}")"
              component recovery-uki-a recovery-a.efi
              component recovery-uki-b recovery-b.efi
              component recovery-entry-a recovery-a.conf
              component recovery-entry-b recovery-b.conf
              component image-metadata ${lib.escapeShellArg metadataFilename}
            } | jq -s .
          )
          jq -S -n \
            --arg schema aos.recovery-bundle/v1 \
            --arg release ${lib.escapeShellArg config.aos.system.version} \
            --arg architecture ${lib.escapeShellArg targetPlatform.constraints.cpu} \
            --arg platform ${lib.escapeShellArg targetPlatform.system} \
            --argjson recovery_abi ${toString config.aos.boot.recovery.abi} \
            --argjson components "$components" \
            '{schema: $schema, release: $release, architecture: $architecture,
              platform: $platform,
              recovery_abi: $recovery_abi, components: $components}' \
            > "$out/recovery-bundle.json"
          openssl dgst -sha256 \
            -sign ${config.aos.boot.secureBoot.dbKey} \
            -out "$out/recovery-bundle.json.sig" \
            "$out/recovery-bundle.json"
        ''}
      '';
    }
  ];
  meta = baseImage.meta or {};
}
