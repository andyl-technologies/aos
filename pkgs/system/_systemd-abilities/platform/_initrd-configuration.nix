##! Renders immutable initrd /etc files with the canonical configuration provider.
{
  lib,
  runCommand,
  jq,
  configurationProvider,
  nodes,
  sourceInputs ? [],
}: let
  # The lowered graph includes configuration children created by composed
  # handlers, such as the initial process configuration. Disabled parents and
  # their children have already been excluded by graph lowering.
  selected = lib.filterAttrs (_: node: let
    identityLength = builtins.length node.identity;
  in
    identityLength
    >= 3
    && builtins.elemAt node.identity (identityLength - 3) == "configuration"
    && builtins.elemAt node.identity (identityLength - 2) == "file"
    && lib.hasPrefix "/etc/" node.input.path)
  nodes;
  invocation = name: node: let
    input = node.input;
    components = lib.splitString "/" (lib.removePrefix "/etc/" input.path);
    immutableFragment = fragment:
      builtins.isString fragment
      || (builtins.isAttrs fragment
        && fragment ? storePath
        && (fragment.credentialPath or null) == null
        && builtins.isString fragment.storePath
        && lib.hasPrefix "/nix/store/" fragment.storePath
        && builtins.all (part: !(builtins.elem part ["" "." ".."]))
        (lib.splitString "/" (lib.removePrefix "/nix/store/" fragment.storePath)));
    immutable = input.content != null || builtins.all immutableFragment input.fragments;
  in
    if lib.hasInfix "\n" input.path || lib.hasInfix "\r" input.path || !(builtins.all (component: !(builtins.elem component ["" "." ".."])) components)
    then throw "Initrd configuration '${name}' must own a canonical path beneath /etc."
    else if !(builtins.elem input.owner [null "root"]) || !(builtins.elem input.group [null "root"])
    then throw "Initrd configuration '${name}' requires an identity unavailable to the image file projection."
    else if input.format == "text" && !immutable
    then throw "Initrd configuration '${name}' requires runtime credentials and cannot enter an immutable image."
    else {
      id = builtins.hashString "sha256" (builtins.toJSON node.identity);
      revision = builtins.hashString "sha256" (builtins.toJSON input);
      action = "apply";
      effect.identity = node.identity;
      inherit input;
    };
  configurations = lib.mapAttrsToList invocation selected;
  paths = map (entry: entry.input.path) configurations;
  configurationJSON =
    if builtins.length paths == builtins.length (lib.unique paths)
    then builtins.toJSON configurations
    else throw "Initrd configuration effects must own distinct image paths.";
in
  runCommand "systemd-initrd-native-configuration" {
    inherit configurationJSON;
    buildDeps = sourceInputs;
    passAsFile = ["configurationJSON"];
  } ''
    # The ordinary provider owns encoding, bounds, modes, and collision checks.
    # Render in scratch space because it refuses to mutate /nix/store paths.
    configuration_root="$TMPDIR/initrd-configuration"
    configuration_state="$TMPDIR/initrd-configuration-state"
    mkdir -p "$configuration_root/etc"
    ${jq}/bin/jq -c '.[]' "$configurationJSONPath" | while IFS= read -r invocation; do
      # Archive ownership is normalized to root by the initrd builder. The
      # unprivileged builder must never attempt chown to host identities.
      printf '%s\n' "$invocation" | ${jq}/bin/jq --arg root "$configuration_root" \
        '.input.path = ($root + .input.path) | .input.owner = null | .input.group = null' \
        > "$TMPDIR/initrd-configuration-invocation.json"
      ${configurationProvider}/bin/aos-configuration-provider \
        --state-directory "$configuration_state" apply \
        < "$TMPDIR/initrd-configuration-invocation.json" > /dev/null
    done
    # Even write-only requested files must remain readable to the unprivileged
    # assembler. The manifest below retains their actual image permissions.
    chmod -R u+rX "$configuration_root"
    mkdir -p "$out"
    cp -a "$configuration_root/." "$out/"
    # Store registration canonicalizes modes. Keep the requested image modes
    # separately so the assembler can restore them before packing the image.
    ${jq}/bin/jq 'map({key: .input.path, value: .input.mode}) | from_entries' \
      "$configurationJSONPath" > "$out/modes.json"
  ''
