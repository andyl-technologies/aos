##! Adds package-owned recovery artifacts to one converted disk image.
{
  baseImage,
  config,
  lib,
  pkgs,
  rawImage,
  targetPlatform,
}:
if !config.aos.boot.recovery.enable
then baseImage
else
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
          cp -a ${baseImage}/. "$out/"

          for component in \
            root.img root.verity root.roothash root.roothash.p7s \
            uki-a.efi uki-b.efi \
            recovery-a.efi recovery-b.efi \
            recovery-a.conf recovery-b.conf; do
            cp "${rawImage}/$component" "$out/$component"
          done

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
              component normal-uki-a uki-a.efi
              component normal-uki-b uki-b.efi
              component recovery-uki-a recovery-a.efi
              component recovery-uki-b recovery-b.efi
              component recovery-entry-a recovery-a.conf
              component recovery-entry-b recovery-b.conf
              component image-metadata image-info.json
            } | jq -s .
          )
          jq -S -n \
            --arg schema aos.recovery-bundle/v1 \
            --arg release ${lib.escapeShellArg config.aos.system.version} \
            --arg architecture ${lib.escapeShellArg targetPlatform.cpu} \
            --arg platform ${lib.escapeShellArg targetPlatform.system} \
            --argjson module_abi ${toString config.aos.system.moduleAbi} \
            --argjson recovery_abi ${toString config.aos.boot.recovery.abi} \
            --argjson components "$components" \
            '{schema: $schema, release: $release, architecture: $architecture,
              platform: $platform, module_abi: $module_abi,
              recovery_abi: $recovery_abi, components: $components}' \
            > "$out/recovery-bundle.json"
          openssl dgst -sha256 \
            -sign ${config.aos.boot.secureBoot.dbKey} \
            -out "$out/recovery-bundle.json.sig" \
            "$out/recovery-bundle.json"
        '';
      }
    ];
    meta = baseImage.meta or {};
  }
