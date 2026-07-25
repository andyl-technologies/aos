# stdenv/toolchains/lib/mk-manifest-tools.nix - manifest-backed tool set
#
# Tier manifests already encode each tool's source, flags, dependencies, and
# install quirks. This helper keeps default.nix files focused on tier ordering:
# choose the manifest keys and the builder profile, then get an attrset whose
# names match the selected tools.
{
  manifest,
  mkTool,
  names,
}:
builtins.listToAttrs (map (name: {
    inherit name;
    value = mkTool manifest.${name};
  })
  names)
