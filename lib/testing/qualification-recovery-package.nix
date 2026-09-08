##! Composes the staged package lifecycle with the booted recovery-image exercise.
{pkgs}: {
  name,
  packageExecutable,
  imageExecutable,
  systemVariant,
}:
assert builtins.substring 0 11 packageExecutable == "/nix/store/";
assert builtins.substring 0 11 imageExecutable == "/nix/store/";
assert systemVariant != "";
  pkgs.writeShellScriptBin name ''
    set -euo pipefail

    export AOS_QUALIFICATION_BOUND_IMAGE_VARIANT=${builtins.toJSON systemVariant}

    # The package adapter proves the staged NAR and APM lifecycle first. Its
    # intermediate response is validated locally; the image adapter emits the
    # single response consumed by the coordinator.
    ${packageExecutable} > package-response.json
    exec ${imageExecutable}
  ''
