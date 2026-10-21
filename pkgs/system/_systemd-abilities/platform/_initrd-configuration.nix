##! Renders immutable initrd /etc files with the canonical configuration provider.
{
  lib,
  runCommand,
  jq,
  configurationProvider,
  effects,
}: let
  selected = lib.filterAttrs (_: effect:
    effect.enable && lib.hasPrefix "/etc/" effect.input.path)
  effects;
  invocation = name: effect: let
    input = effect.input;
    components = lib.splitString "/" (lib.removePrefix "/etc/" input.path);
    literal = input.content != null || builtins.all builtins.isString input.fragments;
  in
    if lib.hasInfix "\n" input.path || lib.hasInfix "\r" input.path || !(builtins.all (component: !(builtins.elem component ["" "." ".."])) components)
    then throw "Initrd configuration '${name}' must own a canonical path beneath /etc."
    else if !(builtins.elem input.owner [null "root"]) || !(builtins.elem input.group [null "root"])
    then throw "Initrd configuration '${name}' requires an identity unavailable to the image file projection."
    else if input.format == "text" && !literal
    then throw "Initrd configuration '${name}' requires runtime credentials and cannot enter an immutable image."
    else {
      id = builtins.hashString "sha256" (builtins.toJSON effect.contract.identity);
      revision = builtins.hashString "sha256" (builtins.toJSON input);
      action = "apply";
      effect.identity = effect.contract.identity;
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
    mkdir -p "$out"
    cp -a "$configuration_root/." "$out/"
  ''
