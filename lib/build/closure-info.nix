##! lib/build/closure-info.nix — Nix DB registration generator
##!
##! Builds a `nix-store --load-db` input stream for the closure of the
##! supplied root paths. This uses Nix's structured `exportReferencesGraph`
##! metadata, so the NAR hashes and sizes come from Nix without re-hashing
##! the closure in the build sandbox.
{
  pkgs,
  lib,
}: {
  rootPaths,
  pname ? "aos-closure-info",
}:
pkgs.mkDerivation {
  inherit pname;
  version = "0";
  src = null;

  # `exportReferencesGraph` is consumed through Nix's structured-attribute
  # files. Use mkDerivation's supported trigger so it does not also emit the
  # inert legacy reference-check attributes that Nix warns about.
  outputChecks = {};
  exportReferencesGraph.closure = rootPaths;

  buildDeps = [
    pkgs.jq
    pkgs.coreutils
  ];

  dontStrip = true;
  dontNukeRefs = true;

  phases = [
    {
      name = "build";
      script = ''
        set -eu
        mkdir -p "$out"

        if [ "$(jq '.closure | length' < "$NIX_ATTRS_JSON_FILE")" -eq 0 ]; then
          : > "$out/registration"
          : > "$out/store-paths"
        else
          jq -r '
            .closure
            | map([.path, .narHash, .narSize, "", (.references | length)] + .references)
            | add
            | map("\(.)\n")
            | add
          ' < "$NIX_ATTRS_JSON_FILE" \
            | head -n -1 > "$out/registration"
          jq -r '.closure[].path' < "$NIX_ATTRS_JSON_FILE" \
            | sort > "$out/store-paths"
        fi
      '';
    }
  ];

  meta = {
    description = "Nix DB registration and path inventory for a closure";
  };
}
