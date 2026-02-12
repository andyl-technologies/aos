# deploy/bundle.nix — AOS update bundle builder
#
# Creates a compressed, self-describing update bundle from the delta
# between an old and new system closure. The bundle contains only the
# store paths present in the new system but absent from the old one,
# minimizing transfer size for incremental updates.
#
# Bundle contents:
#   manifest.json         — version metadata, path list, sizes, hashes
#   store/                — zstd-compressed store path archives
#
# Arguments:
#   pkgs       — AOS package set
#   lib        — AOS library
#   oldSystem  — previous system toplevel (for delta computation)
#   newSystem  — new system toplevel (target of the update)
#   version    — version string for the bundle manifest
#
# Output: $out/aos-update-<version>.tar containing manifest + store paths

{
  pkgs,
  lib,
  oldSystem,
  newSystem,
  version,
}:

let
  # Resolve the toplevel derivation paths.
  oldToplevel = oldSystem.config.system.build.toplevel;
  newToplevel = newSystem.config.system.build.toplevel;

in
pkgs.mkDerivation {
  name = "aos-bundle-${version}";

  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.zstd
    pkgs.tar
    pkgs.bash
  ];

  phases = [
    {
      name = "build-bundle";
      script = ''
        echo "==> Building AOS update bundle v${version}"
        echo "    Old system: ${oldToplevel}"
        echo "    New system: ${newToplevel}"

        WORK=$(mktemp -d)
        mkdir -p "$WORK/store"

        # ── 1. Compute store closures ──────────────────────────────────────
        echo "==> Computing store closures"
        nix-store --query --requisites ${oldToplevel} | sort > "$WORK/old-paths"
        nix-store --query --requisites ${newToplevel} | sort > "$WORK/new-paths"

        # ── 2. Compute delta (paths in new but not in old) ─────────────────
        comm -13 "$WORK/old-paths" "$WORK/new-paths" > "$WORK/delta-paths"

        delta_count=$(wc -l < "$WORK/delta-paths")
        echo "    Old closure: $(wc -l < "$WORK/old-paths") paths"
        echo "    New closure: $(wc -l < "$WORK/new-paths") paths"
        echo "    Delta:       $delta_count new paths"

        if [ "$delta_count" -eq 0 ]; then
          echo "WARNING: No new store paths. Old and new systems may be identical."
        fi

        # ── 3. Compress each delta path with zstd ──────────────────────────
        echo "==> Compressing delta store paths"

        # Build JSON array entries for the manifest while compressing.
        manifest_paths=""
        total_size=0
        compressed_size=0
        count=0

        while IFS= read -r storePath; do
          count=$((count + 1))
          basename=$(basename "$storePath")
          printf '\r    [%d/%d] %s' "$count" "$delta_count" "$basename"

          # Compute hash of the store path contents.
          hash=$(nix-hash --type sha256 --base32 "$storePath")

          # Measure uncompressed size.
          path_size=$(du -sb "$storePath" | cut -f1)
          total_size=$((total_size + path_size))

          # Compress: tar the store path, then zstd compress.
          tar -cf - -C / "$storePath" | zstd -15 -T0 -q > "$WORK/store/''${basename}.tar.zst"

          comp_size=$(stat -c%s "$WORK/store/''${basename}.tar.zst")
          compressed_size=$((compressed_size + comp_size))

          # Accumulate manifest entries.
          if [ -n "$manifest_paths" ]; then
            manifest_paths="$manifest_paths,"
          fi
          manifest_paths="$manifest_paths
            {
              \"path\": \"$storePath\",
              \"hash\": \"$hash\",
              \"size\": $path_size,
              \"compressedSize\": $comp_size,
              \"archive\": \"store/''${basename}.tar.zst\"
            }"
        done < "$WORK/delta-paths"
        echo ""

        # ── 4. Write manifest ──────────────────────────────────────────────
        echo "==> Writing manifest"
        bundle_hash=$(sha256sum "$WORK/delta-paths" | cut -d' ' -f1)
        build_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

        cat > "$WORK/manifest.json" <<MANIFEST
        {
          "version": "${version}",
          "format": 1,
          "timestamp": "$build_timestamp",
          "oldToplevel": "${oldToplevel}",
          "newToplevel": "${newToplevel}",
          "deltaHash": "$bundle_hash",
          "totalSize": $total_size,
          "compressedSize": $compressed_size,
          "pathCount": $delta_count,
          "paths": [$manifest_paths
          ]
        }
        MANIFEST

        echo "    Total size:      $total_size bytes"
        echo "    Compressed size: $compressed_size bytes"

        # ── 5. Create final tarball ────────────────────────────────────────
        echo "==> Creating bundle tarball"
        tar -cf "$WORK/aos-update-${version}.tar" \
          -C "$WORK" \
          manifest.json store/

        mv "$WORK/aos-update-${version}.tar" bundle.tar
        rm -rf "$WORK"
        echo "==> Bundle complete"
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        mv bundle.tar $out/aos-update-${version}.tar

        # Also install the manifest separately for quick inspection.
        # Extract it from the tarball.
        tar -xf $out/aos-update-${version}.tar -C $out manifest.json

        echo "==> Bundle written to $out/aos-update-${version}.tar"
      '';
    }
  ];
}
